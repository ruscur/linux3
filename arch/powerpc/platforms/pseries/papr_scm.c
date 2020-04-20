// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt)	"papr-scm: " fmt

#include <linux/of.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/ndctl.h>
#include <linux/sched.h>
#include <linux/libnvdimm.h>
#include <linux/platform_device.h>
#include <linux/delay.h>

#include <asm/plpar_wrappers.h>
#include <asm/papr_scm.h>
#include <asm/papr_scm_pdsm.h>

#define BIND_ANY_ADDR (~0ul)

#define PAPR_SCM_DIMM_CMD_MASK \
	((1ul << ND_CMD_GET_CONFIG_SIZE) | \
	 (1ul << ND_CMD_GET_CONFIG_DATA) | \
	 (1ul << ND_CMD_SET_CONFIG_DATA) | \
	 (1ul << ND_CMD_CALL))

struct papr_scm_priv {
	struct platform_device *pdev;
	struct device_node *dn;
	uint32_t drc_index;
	uint64_t blocks;
	uint64_t block_size;
	int metadata_size;
	bool is_volatile;

	uint64_t bound_addr;

	struct nvdimm_bus_descriptor bus_desc;
	struct nvdimm_bus *bus;
	struct nvdimm *nvdimm;
	struct resource res;
	struct nd_region *region;
	struct nd_interleave_set nd_set;

	/* Protect dimm health data from concurrent read/writes */
	struct mutex dimm_mutex;

	/* Last time the health information of the dimm was updated */
	unsigned long lasthealth_jiffies;

	/* Health information for the dimm */
	struct nd_papr_pdsm_health health;
};

static int drc_pmem_bind(struct papr_scm_priv *p)
{
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	uint64_t saved = 0;
	uint64_t token;
	int64_t rc;

	/*
	 * When the hypervisor cannot map all the requested memory in a single
	 * hcall it returns H_BUSY and we call again with the token until
	 * we get H_SUCCESS. Aborting the retry loop before getting H_SUCCESS
	 * leave the system in an undefined state, so we wait.
	 */
	token = 0;

	do {
		rc = plpar_hcall(H_SCM_BIND_MEM, ret, p->drc_index, 0,
				p->blocks, BIND_ANY_ADDR, token);
		token = ret[0];
		if (!saved)
			saved = ret[1];
		cond_resched();
	} while (rc == H_BUSY);

	if (rc)
		return rc;

	p->bound_addr = saved;
	dev_dbg(&p->pdev->dev, "bound drc 0x%x to 0x%lx\n",
		p->drc_index, (unsigned long)saved);
	return rc;
}

static void drc_pmem_unbind(struct papr_scm_priv *p)
{
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	uint64_t token = 0;
	int64_t rc;

	dev_dbg(&p->pdev->dev, "unbind drc 0x%x\n", p->drc_index);

	/* NB: unbind has the same retry requirements as drc_pmem_bind() */
	do {

		/* Unbind of all SCM resources associated with drcIndex */
		rc = plpar_hcall(H_SCM_UNBIND_ALL, ret, H_UNBIND_SCOPE_DRC,
				 p->drc_index, token);
		token = ret[0];

		/* Check if we are stalled for some time */
		if (H_IS_LONG_BUSY(rc)) {
			msleep(get_longbusy_msecs(rc));
			rc = H_BUSY;
		} else if (rc == H_BUSY) {
			cond_resched();
		}

	} while (rc == H_BUSY);

	if (rc)
		dev_err(&p->pdev->dev, "unbind error: %lld\n", rc);
	else
		dev_dbg(&p->pdev->dev, "unbind drc 0x%x complete\n",
			p->drc_index);

	return;
}

static int drc_pmem_query_n_bind(struct papr_scm_priv *p)
{
	unsigned long start_addr;
	unsigned long end_addr;
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	int64_t rc;


	rc = plpar_hcall(H_SCM_QUERY_BLOCK_MEM_BINDING, ret,
			 p->drc_index, 0);
	if (rc)
		goto err_out;
	start_addr = ret[0];

	/* Make sure the full region is bound. */
	rc = plpar_hcall(H_SCM_QUERY_BLOCK_MEM_BINDING, ret,
			 p->drc_index, p->blocks - 1);
	if (rc)
		goto err_out;
	end_addr = ret[0];

	if ((end_addr - start_addr) != ((p->blocks - 1) * p->block_size))
		goto err_out;

	p->bound_addr = start_addr;
	dev_dbg(&p->pdev->dev, "bound drc 0x%x to 0x%lx\n", p->drc_index, start_addr);
	return rc;

err_out:
	dev_info(&p->pdev->dev,
		 "Failed to query, trying an unbind followed by bind");
	drc_pmem_unbind(p);
	return drc_pmem_bind(p);
}

/* Min interval in seconds between successive H_SCM_HEALTH hcalls */
#define MIN_HEALTH_QUERY_INTERVAL 60

/*
 * Issue hcall if needed to retrieve dimm health info. Information is cached
 * and subsequent calls may return success without issueing the hcall.
 * Use 'force == true' to force issue of the hcall ignoring the cache
 * timeout.
 */
static int drc_pmem_query_health(struct papr_scm_priv *p, bool force)
{
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	s64 rc;
	unsigned long cache_timeout;
	u64 health;

	/* Protect concurrent modifications to papr_scm_priv */
	rc = mutex_lock_interruptible(&p->dimm_mutex);
	if (rc)
		return rc;

	/* Jiffies offset for which the health data is assumed to be same */
	cache_timeout = p->lasthealth_jiffies +
		msecs_to_jiffies(MIN_HEALTH_QUERY_INTERVAL * 1000);

	/* Dont issue the hcall if health information is relatively new */
	if (!force && time_after(cache_timeout, jiffies)) {
		rc = 0;
		goto out;
	}

	/* issue the hcall */
	rc = plpar_hcall(H_SCM_HEALTH, ret, p->drc_index);
	if (rc != H_SUCCESS) {
		dev_err(&p->pdev->dev,
			 "Failed to query health information, Err:%lld\n", rc);
		rc = -ENXIO;
		goto out;
	}

	p->lasthealth_jiffies = jiffies;
	health = ret[0] & ret[1];

	dev_dbg(&p->pdev->dev,
		"Queried dimm health info. Bitmap:0x%016lx Mask:0x%016lx\n",
		ret[0], ret[1]);

	memset(&p->health, 0, sizeof(p->health));

	/* Check for various masks in bitmap and set the buffer */
	if (health & PAPR_SCM_DIMM_UNARMED_MASK)
		p->health.dimm_unarmed = 1;

	if (health & PAPR_SCM_DIMM_BAD_SHUTDOWN_MASK)
		p->health.dimm_bad_shutdown = 1;

	if (health & PAPR_SCM_DIMM_BAD_RESTORE_MASK)
		p->health.dimm_bad_restore = 1;

	if (health & PAPR_SCM_DIMM_ENCRYPTED)
		p->health.dimm_encrypted = 1;

	if (health & PAPR_SCM_DIMM_SCRUBBED_AND_LOCKED) {
		p->health.dimm_locked = 1;
		p->health.dimm_scrubbed = 1;
	}

	if (health & PAPR_SCM_DIMM_HEALTH_UNHEALTHY)
		p->health.dimm_health = PAPR_PDSM_DIMM_UNHEALTHY;

	if (health & PAPR_SCM_DIMM_HEALTH_CRITICAL)
		p->health.dimm_health = PAPR_PDSM_DIMM_CRITICAL;

	if (health & PAPR_SCM_DIMM_HEALTH_FATAL)
		p->health.dimm_health = PAPR_PDSM_DIMM_FATAL;

out:
	mutex_unlock(&p->dimm_mutex);
	return rc;
}

static int papr_scm_meta_get(struct papr_scm_priv *p,
			     struct nd_cmd_get_config_data_hdr *hdr)
{
	unsigned long data[PLPAR_HCALL_BUFSIZE];
	unsigned long offset, data_offset;
	int len, read;
	int64_t ret;

	if ((hdr->in_offset + hdr->in_length) > p->metadata_size)
		return -EINVAL;

	for (len = hdr->in_length; len; len -= read) {

		data_offset = hdr->in_length - len;
		offset = hdr->in_offset + data_offset;

		if (len >= 8)
			read = 8;
		else if (len >= 4)
			read = 4;
		else if (len >= 2)
			read = 2;
		else
			read = 1;

		ret = plpar_hcall(H_SCM_READ_METADATA, data, p->drc_index,
				  offset, read);

		if (ret == H_PARAMETER) /* bad DRC index */
			return -ENODEV;
		if (ret)
			return -EINVAL; /* other invalid parameter */

		switch (read) {
		case 8:
			*(uint64_t *)(hdr->out_buf + data_offset) = be64_to_cpu(data[0]);
			break;
		case 4:
			*(uint32_t *)(hdr->out_buf + data_offset) = be32_to_cpu(data[0] & 0xffffffff);
			break;

		case 2:
			*(uint16_t *)(hdr->out_buf + data_offset) = be16_to_cpu(data[0] & 0xffff);
			break;

		case 1:
			*(uint8_t *)(hdr->out_buf + data_offset) = (data[0] & 0xff);
			break;
		}
	}
	return 0;
}

static int papr_scm_meta_set(struct papr_scm_priv *p,
			     struct nd_cmd_set_config_hdr *hdr)
{
	unsigned long offset, data_offset;
	int len, wrote;
	unsigned long data;
	__be64 data_be;
	int64_t ret;

	if ((hdr->in_offset + hdr->in_length) > p->metadata_size)
		return -EINVAL;

	for (len = hdr->in_length; len; len -= wrote) {

		data_offset = hdr->in_length - len;
		offset = hdr->in_offset + data_offset;

		if (len >= 8) {
			data = *(uint64_t *)(hdr->in_buf + data_offset);
			data_be = cpu_to_be64(data);
			wrote = 8;
		} else if (len >= 4) {
			data = *(uint32_t *)(hdr->in_buf + data_offset);
			data &= 0xffffffff;
			data_be = cpu_to_be32(data);
			wrote = 4;
		} else if (len >= 2) {
			data = *(uint16_t *)(hdr->in_buf + data_offset);
			data &= 0xffff;
			data_be = cpu_to_be16(data);
			wrote = 2;
		} else {
			data_be = *(uint8_t *)(hdr->in_buf + data_offset);
			data_be &= 0xff;
			wrote = 1;
		}

		ret = plpar_hcall_norets(H_SCM_WRITE_METADATA, p->drc_index,
					 offset, data_be, wrote);
		if (ret == H_PARAMETER) /* bad DRC index */
			return -ENODEV;
		if (ret)
			return -EINVAL; /* other invalid parameter */
	}

	return 0;
}

/*
 * Validate the inputs args to dimm-control function and return '0' if valid.
 * This also does initial sanity validation to ND_CMD_CALL sub-command packages.
 */
static int is_cmd_valid(struct nvdimm *nvdimm, unsigned int cmd, void *buf,
		       unsigned int buf_len)
{
	unsigned long cmd_mask = PAPR_SCM_DIMM_CMD_MASK;
	struct nd_pdsm_cmd_pkg *pkg = nd_to_pdsm_cmd_pkg(buf);
	struct papr_scm_priv *p;

	/* Only dimm-specific calls are supported atm */
	if (!nvdimm)
		return -EINVAL;

	/* get the provider date from struct nvdimm */
	p = nvdimm_provider_data(nvdimm);

	if (!test_bit(cmd, &cmd_mask)) {
		dev_dbg(&p->pdev->dev, "Unsupported cmd=%u\n", cmd);
		return -EINVAL;
	} else if (cmd == ND_CMD_CALL) {

		/* Verify the envelope package */
		if (!buf || buf_len < sizeof(struct nd_pdsm_cmd_pkg)) {
			dev_dbg(&p->pdev->dev, "Invalid pkg size=%u\n",
				buf_len);
			return -EINVAL;
		}

		/* Verify that the PDSM family is valid */
		if (pkg->hdr.nd_family != NVDIMM_FAMILY_PAPR_SCM) {
			dev_dbg(&p->pdev->dev, "Invalid pkg family=0x%llx\n",
				pkg->hdr.nd_family);
			return -EINVAL;

		}

		/* We except a payload with all PDSM commands */
		if (pdsm_cmd_to_payload(pkg) == NULL) {
			dev_dbg(&p->pdev->dev,
				"Empty payload for sub-command=0x%llx\n",
				pkg->hdr.nd_command);
			return -EINVAL;
		}
	}

	/* Command looks valid */
	return 0;
}

/* Fetch the DIMM health info and populate it in provided package. */
static int papr_scm_get_health(struct papr_scm_priv *p,
			       struct nd_pdsm_cmd_pkg *pkg)
{
	int rc;
	size_t copysize = sizeof(p->health);

	/* Always fetch upto date dimm health data ignoring cached values */
	rc = drc_pmem_query_health(p, true);
	if (rc)
		goto out;
	/*
	 * If the requested payload version is greater than one we know
	 * about, return the payload version we know about and let
	 * caller/userspace handle.
	 */
	if (pkg->payload_version > ND_PAPR_PDSM_HEALTH_VERSION)
		pkg->payload_version = ND_PAPR_PDSM_HEALTH_VERSION;

	if (pkg->hdr.nd_size_out < copysize) {
		dev_dbg(&p->pdev->dev, "Truncated payload (%u). Expected (%lu)",
			pkg->hdr.nd_size_out, copysize);
		rc = -ENOSPC;
		goto out;
	}

	dev_dbg(&p->pdev->dev, "Copying payload size=%lu version=0x%x\n",
		copysize, pkg->payload_version);

	/*
	 * Copy a subset of health struct based on copysize ensuring dimm mutex
	 * is locked to prevent a simultaneous read/write of health data
	 */
	rc = mutex_lock_interruptible(&p->dimm_mutex);
	if (rc)
		goto out;

	/* Copy the health struct to the payload */
	memcpy(pdsm_cmd_to_payload(pkg), &p->health, copysize);

	mutex_unlock(&p->dimm_mutex);

	pkg->hdr.nd_fw_size = copysize;

out:
	/*
	 * Put the error in out package and return success from function
	 * so that errors if any are propogated back to userspace.
	 */
	pkg->cmd_status = rc;
	dev_dbg(&p->pdev->dev, "completion code = %d\n", rc);

	return 0;
}

static int papr_scm_service_pdsm(struct papr_scm_priv *p,
				struct nd_pdsm_cmd_pkg *call_pkg)
{
	/* unknown subcommands return error in packages */
	if (call_pkg->hdr.nd_command <= PAPR_SCM_PDSM_MIN ||
	    call_pkg->hdr.nd_command >= PAPR_SCM_PDSM_MAX) {
		dev_dbg(&p->pdev->dev, "Invalid PDSM request 0x%llx\n",
			call_pkg->hdr.nd_command);
		call_pkg->cmd_status = -EINVAL;
		return 0;
	}

	/* Depending on the DSM command call appropriate service routine */
	switch (call_pkg->hdr.nd_command) {
	case PAPR_SCM_PDSM_HEALTH:
		return papr_scm_get_health(p, call_pkg);

	default:
		dev_dbg(&p->pdev->dev, "Unsupported PDSM request 0x%llx\n",
			call_pkg->hdr.nd_command);
		call_pkg->cmd_status = -ENOENT;
		return 0;
	}
}

int papr_scm_ndctl(struct nvdimm_bus_descriptor *nd_desc, struct nvdimm *nvdimm,
		unsigned int cmd, void *buf, unsigned int buf_len, int *cmd_rc)
{
	struct nd_cmd_get_config_size *get_size_hdr;
	struct papr_scm_priv *p;
	struct nd_pdsm_cmd_pkg *call_pkg = NULL;
	int rc;

	/* Use a local variable in case cmd_rc pointer is NULL */
	if (cmd_rc == NULL)
		cmd_rc = &rc;

	*cmd_rc = is_cmd_valid(nvdimm, cmd, buf, buf_len);
	if (*cmd_rc) {
		pr_debug("Invalid cmd=0x%x. Err=%d\n", cmd, *cmd_rc);
		return *cmd_rc;
	}

	p = nvdimm_provider_data(nvdimm);

	switch (cmd) {
	case ND_CMD_GET_CONFIG_SIZE:
		get_size_hdr = buf;

		get_size_hdr->status = 0;
		get_size_hdr->max_xfer = 8;
		get_size_hdr->config_size = p->metadata_size;
		*cmd_rc = 0;
		break;

	case ND_CMD_GET_CONFIG_DATA:
		*cmd_rc = papr_scm_meta_get(p, buf);
		break;

	case ND_CMD_SET_CONFIG_DATA:
		*cmd_rc = papr_scm_meta_set(p, buf);
		break;

	case ND_CMD_CALL:
		call_pkg = nd_to_pdsm_cmd_pkg(buf);
		*cmd_rc = papr_scm_service_pdsm(p, call_pkg);
		break;

	default:
		dev_dbg(&p->pdev->dev, "Unknown command = %d\n", cmd);
		*cmd_rc = -EINVAL;
	}

	dev_dbg(&p->pdev->dev, "returned with cmd_rc = %d\n", *cmd_rc);

	return *cmd_rc;
}

static inline int papr_scm_node(int node)
{
	int min_dist = INT_MAX, dist;
	int nid, min_node;

	if ((node == NUMA_NO_NODE) || node_online(node))
		return node;

	min_node = first_online_node;
	for_each_online_node(nid) {
		dist = node_distance(node, nid);
		if (dist < min_dist) {
			min_dist = dist;
			min_node = nid;
		}
	}
	return min_node;
}

static ssize_t flags_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct nvdimm *dimm = to_nvdimm(dev);
	struct papr_scm_priv *p = nvdimm_provider_data(dimm);
	int rc;

	rc = drc_pmem_query_health(p, false);
	if (rc)
		return rc;

	/* Protect against concurrent modifications to papr_scm_priv */
	rc = mutex_lock_interruptible(&p->dimm_mutex);
	if (rc)
		return rc;

	if (p->health.dimm_unarmed)
		rc += sprintf(buf, "not_armed ");

	if (p->health.dimm_bad_shutdown)
		rc += sprintf(buf + rc, "flush_fail ");

	if (p->health.dimm_bad_restore)
		rc += sprintf(buf + rc, "restore_fail ");

	if (p->health.dimm_encrypted)
		rc += sprintf(buf + rc, "encrypted ");

	if (p->health.dimm_health)
		rc += sprintf(buf + rc, "smart_notify ");

	if (p->health.dimm_scrubbed)
		rc += sprintf(buf + rc, "scrubbed ");

	if (p->health.dimm_locked)
		rc += sprintf(buf + rc, "locked ");

	if (rc > 0)
		rc += sprintf(buf + rc, "\n");

	mutex_unlock(&p->dimm_mutex);
	return rc;
}
DEVICE_ATTR_RO(flags);

/* papr_scm specific dimm attributes */
static struct attribute *papr_scm_nd_attributes[] = {
	&dev_attr_flags.attr,
	NULL,
};

static struct attribute_group papr_scm_nd_attribute_group = {
	.name = "papr",
	.attrs = papr_scm_nd_attributes,
};

static const struct attribute_group *papr_scm_dimm_attr_groups[] = {
	&papr_scm_nd_attribute_group,
	NULL,
};

static int papr_scm_nvdimm_init(struct papr_scm_priv *p)
{
	struct device *dev = &p->pdev->dev;
	struct nd_mapping_desc mapping;
	struct nd_region_desc ndr_desc;
	unsigned long dimm_flags;
	int target_nid, online_nid;

	p->bus_desc.ndctl = papr_scm_ndctl;
	p->bus_desc.module = THIS_MODULE;
	p->bus_desc.of_node = p->pdev->dev.of_node;
	p->bus_desc.provider_name = kstrdup(p->pdev->name, GFP_KERNEL);

	if (!p->bus_desc.provider_name)
		return -ENOMEM;

	p->bus = nvdimm_bus_register(NULL, &p->bus_desc);
	if (!p->bus) {
		dev_err(dev, "Error creating nvdimm bus %pOF\n", p->dn);
		kfree(p->bus_desc.provider_name);
		return -ENXIO;
	}

	dimm_flags = 0;
	set_bit(NDD_ALIASING, &dimm_flags);

	p->nvdimm = nvdimm_create(p->bus, p, papr_scm_dimm_attr_groups,
				  dimm_flags, PAPR_SCM_DIMM_CMD_MASK, 0, NULL);
	if (!p->nvdimm) {
		dev_err(dev, "Error creating DIMM object for %pOF\n", p->dn);
		goto err;
	}

	if (nvdimm_bus_check_dimm_count(p->bus, 1))
		goto err;

	/* now add the region */

	memset(&mapping, 0, sizeof(mapping));
	mapping.nvdimm = p->nvdimm;
	mapping.start = 0;
	mapping.size = p->blocks * p->block_size; // XXX: potential overflow?

	memset(&ndr_desc, 0, sizeof(ndr_desc));
	target_nid = dev_to_node(&p->pdev->dev);
	online_nid = papr_scm_node(target_nid);
	ndr_desc.numa_node = online_nid;
	ndr_desc.target_node = target_nid;
	ndr_desc.res = &p->res;
	ndr_desc.of_node = p->dn;
	ndr_desc.provider_data = p;
	ndr_desc.mapping = &mapping;
	ndr_desc.num_mappings = 1;
	ndr_desc.nd_set = &p->nd_set;

	if (p->is_volatile)
		p->region = nvdimm_volatile_region_create(p->bus, &ndr_desc);
	else
		p->region = nvdimm_pmem_region_create(p->bus, &ndr_desc);
	if (!p->region) {
		dev_err(dev, "Error registering region %pR from %pOF\n",
				ndr_desc.res, p->dn);
		goto err;
	}
	if (target_nid != online_nid)
		dev_info(dev, "Region registered with target node %d and online node %d",
			 target_nid, online_nid);

	return 0;

err:	nvdimm_bus_unregister(p->bus);
	kfree(p->bus_desc.provider_name);
	return -ENXIO;
}

static int papr_scm_probe(struct platform_device *pdev)
{
	struct device_node *dn = pdev->dev.of_node;
	u32 drc_index, metadata_size;
	u64 blocks, block_size;
	struct papr_scm_priv *p;
	const char *uuid_str;
	u64 uuid[2];
	int rc;

	/* check we have all the required DT properties */
	if (of_property_read_u32(dn, "ibm,my-drc-index", &drc_index)) {
		dev_err(&pdev->dev, "%pOF: missing drc-index!\n", dn);
		return -ENODEV;
	}

	if (of_property_read_u64(dn, "ibm,block-size", &block_size)) {
		dev_err(&pdev->dev, "%pOF: missing block-size!\n", dn);
		return -ENODEV;
	}

	if (of_property_read_u64(dn, "ibm,number-of-blocks", &blocks)) {
		dev_err(&pdev->dev, "%pOF: missing number-of-blocks!\n", dn);
		return -ENODEV;
	}

	if (of_property_read_string(dn, "ibm,unit-guid", &uuid_str)) {
		dev_err(&pdev->dev, "%pOF: missing unit-guid!\n", dn);
		return -ENODEV;
	}


	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	/* Initialize the dimm mutex */
	mutex_init(&p->dimm_mutex);

	/* optional DT properties */
	of_property_read_u32(dn, "ibm,metadata-size", &metadata_size);

	p->dn = dn;
	p->drc_index = drc_index;
	p->block_size = block_size;
	p->blocks = blocks;
	p->is_volatile = !of_property_read_bool(dn, "ibm,cache-flush-required");

	/* We just need to ensure that set cookies are unique across */
	uuid_parse(uuid_str, (uuid_t *) uuid);
	/*
	 * cookie1 and cookie2 are not really little endian
	 * we store a little endian representation of the
	 * uuid str so that we can compare this with the label
	 * area cookie irrespective of the endian config with which
	 * the kernel is built.
	 */
	p->nd_set.cookie1 = cpu_to_le64(uuid[0]);
	p->nd_set.cookie2 = cpu_to_le64(uuid[1]);

	/* might be zero */
	p->metadata_size = metadata_size;
	p->pdev = pdev;

	/* request the hypervisor to bind this region to somewhere in memory */
	rc = drc_pmem_bind(p);

	/* If phyp says drc memory still bound then force unbound and retry */
	if (rc == H_OVERLAP)
		rc = drc_pmem_query_n_bind(p);

	if (rc != H_SUCCESS) {
		dev_err(&p->pdev->dev, "bind err: %d\n", rc);
		rc = -ENXIO;
		goto err;
	}

	/* setup the resource for the newly bound range */
	p->res.start = p->bound_addr;
	p->res.end   = p->bound_addr + p->blocks * p->block_size - 1;
	p->res.name  = pdev->name;
	p->res.flags = IORESOURCE_MEM;

	rc = papr_scm_nvdimm_init(p);
	if (rc)
		goto err2;

	platform_set_drvdata(pdev, p);

	return 0;

err2:	drc_pmem_unbind(p);
err:	kfree(p);
	return rc;
}

static int papr_scm_remove(struct platform_device *pdev)
{
	struct papr_scm_priv *p = platform_get_drvdata(pdev);

	nvdimm_bus_unregister(p->bus);
	drc_pmem_unbind(p);
	kfree(p->bus_desc.provider_name);
	kfree(p);

	return 0;
}

static const struct of_device_id papr_scm_match[] = {
	{ .compatible = "ibm,pmemory" },
	{ },
};

static struct platform_driver papr_scm_driver = {
	.probe = papr_scm_probe,
	.remove = papr_scm_remove,
	.driver = {
		.name = "papr_scm",
		.of_match_table = papr_scm_match,
	},
};

module_platform_driver(papr_scm_driver);
MODULE_DEVICE_TABLE(of, papr_scm_match);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("IBM Corporation");
