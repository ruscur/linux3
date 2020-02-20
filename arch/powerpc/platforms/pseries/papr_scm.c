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
#include <asm/papr_scm_dsm.h>

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

	/* Protect dimm data from concurrent access */
	struct mutex dimm_mutex;

	/* Health information for the dimm */
	struct nd_papr_scm_dimm_health_stat health;

	/* length of the stat buffer as expected by phyp */
	size_t len_stat_buffer;
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

static int drc_pmem_query_stats(struct papr_scm_priv *p,
				struct papr_scm_perf_stats *stats,
				size_t size, uint64_t *out)
{
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	int64_t rc;

	/* In case of no out buffer ignore the size */
	if (!stats)
		size = 0;

	/*
	 * Do the HCALL asking PHYP for info and if R4 was requested
	 * return its value in 'out' variable.
	 */
	rc = plpar_hcall(H_SCM_PERFORMANCE_STATS, ret, p->drc_index,
			 __pa(stats), size);
	if (out)
		*out =  be64_to_cpu(ret[0]);

	switch (rc) {
	case H_SUCCESS:
		/* Handle the case where size of stat buffer was requested */
		if (size != 0)
			dev_dbg(&p->pdev->dev,
				"Performance stats returned %d stats\n",
				be32_to_cpu(stats->num_statistics));
		else
			dev_dbg(&p->pdev->dev,
				"Performance stats size %lld\n",
				be64_to_cpu(ret[0]));
		return 0;
	case H_PARTIAL:
		dev_err(&p->pdev->dev,
			 "Unknown performance stats, Err:0x%016llX\n",
			be64_to_cpu(ret[0]));
		return -ENOENT;
	default:
		dev_err(&p->pdev->dev,
			 "Failed to query performance stats, Err:%lld\n", rc);
		return -ENXIO;
	}
}

static int drc_pmem_query_health(struct papr_scm_priv *p)
{
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	int64_t rc;
	__be64 health;

	rc = plpar_hcall(H_SCM_HEALTH, ret, p->drc_index);
	if (rc != H_SUCCESS) {
		dev_err(&p->pdev->dev,
			 "Failed to query health information, Err:%lld\n", rc);
		return -ENXIO;
	}

	/* Protect modifications to papr_scm_priv with the mutex */
	rc = mutex_lock_interruptible(&p->dimm_mutex);
	if (rc)
		return rc;

	/* Store the retrieved health information in dimm platform data */
	health = ret[0] & ret[1];

	dev_dbg(&p->pdev->dev,
		"Queried dimm health info. Bitmap:0x%016llx Mask:0x%016llx\n",
		be64_to_cpu(ret[0]),
		be64_to_cpu(ret[1]));

	memset(&p->health, 0, sizeof(p->health));

	/* Check for various masks in bitmap and set the buffer */
	if (health & PAPR_SCM_DIMM_UNARMED_MASK)
		p->health.dimm_unarmed = true;

	if (health & PAPR_SCM_DIMM_BAD_SHUTDOWN_MASK)
		p->health.dimm_bad_shutdown = true;

	if (health & PAPR_SCM_DIMM_BAD_RESTORE_MASK)
		p->health.dimm_bad_restore = true;

	if (health & PAPR_SCM_DIMM_ENCRYPTED)
		p->health.dimm_encrypted = true;

	if (health & PAPR_SCM_DIMM_SCRUBBED_AND_LOCKED) {
		p->health.dimm_locked = true;
		p->health.dimm_scrubbed = true;
	}

	if (health & PAPR_SCM_DIMM_HEALTH_UNHEALTHY)
		p->health.dimm_health = DSM_PAPR_SCM_DIMM_UNHEALTHY;

	if (health & PAPR_SCM_DIMM_HEALTH_CRITICAL)
		p->health.dimm_health = DSM_PAPR_SCM_DIMM_CRITICAL;

	if (health & PAPR_SCM_DIMM_HEALTH_FATAL)
		p->health.dimm_health = DSM_PAPR_SCM_DIMM_FATAL;

	mutex_unlock(&p->dimm_mutex);
	return 0;
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
 * Validate the input to dimm-control function and return papr_scm specific
 * commands. This does sanity validation to ND_CMD_CALL sub-command packages.
 */
static int cmd_to_func(struct nvdimm *nvdimm, unsigned int cmd, void *buf,
		       unsigned int buf_len)
{
	unsigned long cmd_mask = PAPR_SCM_DIMM_CMD_MASK;
	struct nd_papr_scm_cmd_pkg *pkg = nd_to_papr_cmd_pkg(buf);

	/* Only dimm-specific calls are supported atm */
	if (!nvdimm)
		return -EINVAL;

	if (!test_bit(cmd, &cmd_mask)) {
		pr_debug("%s: Unsupported cmd=%u\n", __func__, cmd);
		return -EINVAL;
	} else if (cmd != ND_CMD_CALL) {
		return cmd;
	}

	/* cmd == ND_CMD_CALL so verify the envelop package */

	if (!buf || buf_len < sizeof(struct nd_papr_scm_cmd_pkg)) {
		pr_debug("%s: Invalid pkg size=%u\n", __func__, buf_len);
		return -EINVAL;
	}

	if (pkg->hdr.nd_family != NVDIMM_FAMILY_PAPR_SCM) {
		pr_debug("%s: Invalid pkg family=0x%llx\n", __func__,
			 pkg->hdr.nd_family);
		return -EINVAL;

	}

	if (pkg->hdr.nd_command <= DSM_PAPR_SCM_MIN ||
	    pkg->hdr.nd_command >= DSM_PAPR_SCM_MAX) {

		/* for unknown subcommands return ND_CMD_CALL */
		pr_debug("%s: Unknown sub-command=0x%llx\n", __func__,
			 pkg->hdr.nd_command);
		return ND_CMD_CALL;
	}

	/* We except a payload with all DSM commands */
	if (papr_scm_pcmd_to_payload(pkg) == NULL) {
		pr_debug("%s: Empty patload for sub-command=0x%llx\n", __func__,
			 pkg->hdr.nd_command);
		return -EINVAL;
	}

	/* Return the DSM_PAPR_SCM_* command */
	return pkg->hdr.nd_command;
}

/*
 * Fetch the DIMM health info and populate it in provided papr_scm package.
 * Since the caller can request a different version of payload and each new
 * version of struct nd_papr_scm_dimm_health_stat is a proper-subset of
 * previous version hence we return a subset of the cached 'struct
 * nd_papr_scm_dimm_health_stat' depending on the payload version requested.
 */
static int papr_scm_get_health(struct papr_scm_priv *p,
			       struct nd_papr_scm_cmd_pkg *pkg)
{
	int rc;
	size_t copysize;
	/* Map version to number of bytes to be copied to payload */
	const size_t copysizes[] = {
		[1] =
		sizeof(struct nd_papr_scm_dimm_health_stat_v1),

		/*  This should always be preset */
		[ND_PAPR_SCM_DIMM_HEALTH_VERSION] =
		sizeof(struct nd_papr_scm_dimm_health_stat),
	};

	rc = drc_pmem_query_health(p);
	if (rc)
		goto out;
	/*
	 * If the requested payload version is greater than one we know
	 * aboute, return the payload version we know about and let
	 * caller/userspace handle the mess.
	 */
	if (pkg->payload_version > ND_PAPR_SCM_DIMM_HEALTH_VERSION)
		pkg->payload_version = ND_PAPR_SCM_DIMM_HEALTH_VERSION;

	copysize = copysizes[pkg->payload_version];
	if (!copysize) {
		dev_dbg(&p->pdev->dev, "%s Unsupported payload version=0x%x\n",
			__func__, pkg->payload_version);
		rc = -ENOSPC;
		goto out;
	}

	if (pkg->hdr.nd_size_out < copysize) {
		dev_dbg(&p->pdev->dev, "%s Payload not large enough\n",
			__func__);
		dev_dbg(&p->pdev->dev, "%s Expected %lu, available %u\n",
			__func__, copysize, pkg->hdr.nd_size_out);
		rc = -ENOSPC;
		goto out;
	}

	dev_dbg(&p->pdev->dev, "%s Copying payload size=%lu version=0x%x\n",
		__func__, copysize, pkg->payload_version);

	/* Copy a subset of health struct based on copysize */
	memcpy(papr_scm_pcmd_to_payload(pkg), &p->health, copysize);
	pkg->hdr.nd_fw_size = copysize;

out:
	/*
	 * Put the error in out package and return success from function
	 * so that errors if any are propogated back to userspace.
	 */
	pkg->cmd_status = rc;
	dev_dbg(&p->pdev->dev, "%s completion code = %d\n", __func__, rc);

	return 0;
}

int papr_scm_ndctl(struct nvdimm_bus_descriptor *nd_desc, struct nvdimm *nvdimm,
		unsigned int cmd, void *buf, unsigned int buf_len, int *cmd_rc)
{
	struct nd_cmd_get_config_size *get_size_hdr;
	struct papr_scm_priv *p;
	struct nd_papr_scm_cmd_pkg *call_pkg = NULL;
	int cmd_in, rc;

	/* Use a local variable in case cmd_rc pointer is NULL */
	if (cmd_rc == NULL)
		cmd_rc = &rc;

	cmd_in = cmd_to_func(nvdimm, cmd, buf, buf_len);
	if (cmd_in < 0) {
		pr_debug("%s: Invalid cmd=%u. Err=%d\n", __func__, cmd, cmd_in);
		return cmd_in;
	}

	p = nvdimm_provider_data(nvdimm);

	switch (cmd_in) {
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
		/* This happens if subcommand package sanity fails */
		call_pkg = nd_to_papr_cmd_pkg(buf);
		call_pkg->cmd_status = -ENOENT;
		*cmd_rc = 0;
		break;

	case DSM_PAPR_SCM_HEALTH:
		call_pkg = nd_to_papr_cmd_pkg(buf);
		*cmd_rc = papr_scm_get_health(p, call_pkg);
		break;

	default:
		dev_dbg(&p->pdev->dev, "Unknown command = %d\n", cmd_in);
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

static ssize_t papr_perf_stats_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct nvdimm *dimm = to_nvdimm(dev);
	struct papr_scm_priv *p = nvdimm_provider_data(dimm);
	struct papr_scm_perf_stats *retbuffer;
	struct papr_scm_perf_stat *stat;
	uint64_t statid, val;
	int rc, i;

	if (!p->len_stat_buffer)
		return -ENOENT;

	/* Return buffer for phyp where stats are written */
	retbuffer = kzalloc(p->len_stat_buffer, GFP_KERNEL);
	if (!retbuffer)
		return -ENOMEM;

	/* Setup the buffer */
	memcpy(retbuffer->eye_catcher, PAPR_SCM_PERF_STATS_EYECATCHER,
	       sizeof(retbuffer->eye_catcher));
	retbuffer->stats_version = cpu_to_be32(0x1);
	retbuffer->num_statistics = 0;

	rc = drc_pmem_query_stats(p, retbuffer, p->len_stat_buffer, NULL);
	if (rc)
		goto out;

	/*
	 * Go through the returned output buffer and print stats and values.
	 * Since statistic_id is essentially a char string of 8 bytes encoded
	 * as a __be64, simply use the string format specifier to print it.
	 */
	for (i = 0, stat = retbuffer->scm_statistics;
	    i < be32_to_cpu(retbuffer->num_statistics); ++i, ++stat) {
		statid = be64_to_cpu(stat->statistic_id);
		val = be64_to_cpu(stat->statistic_value);
		rc += sprintf(buf + rc, "%.8s => 0x%016llX\n",
			      (char *) &(statid), val);
	}
out:
	kfree(retbuffer);
	return rc;

}
DEVICE_ATTR_RO(papr_perf_stats);

static ssize_t papr_flags_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct nvdimm *dimm = to_nvdimm(dev);
	struct papr_scm_priv *p = nvdimm_provider_data(dimm);
	int rc;

	rc = drc_pmem_query_health(p);
	if (rc)
		return rc;

	/* Protect against modifications to papr_scm_priv with the mutex */
	rc = mutex_lock_interruptible(&p->dimm_mutex);
	if (rc)
		return rc;

	if (p->health.dimm_unarmed)
		rc += sprintf(buf, "not_armed ");

	if (p->health.dimm_bad_shutdown)
		rc += sprintf(buf + rc, "save_fail ");

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
DEVICE_ATTR_RO(papr_flags);

/* papr_scm specific dimm attributes */
static struct attribute *papr_scm_nd_attributes[] = {
	&dev_attr_papr_flags.attr,
	&dev_attr_papr_perf_stats.attr,
	NULL,
};

static struct attribute_group papr_scm_nd_attribute_group = {
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
	uint64_t stat_size;

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

	/* Try retriving the stat buffer and see if its supported */
	if (!drc_pmem_query_stats(p, NULL, 0, &stat_size)) {
		p->len_stat_buffer = (size_t)stat_size;
		dev_dbg(&p->pdev->dev, "Max dimm perf stats size %ld bytes\n",
			p->len_stat_buffer);
	} else {
		p->len_stat_buffer = 0;
		dev_dbg(&p->pdev->dev, "Unable to retrieve performace stats\n");
		dev_info(&p->pdev->dev, "Limited dimm info available\n");
	}

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
