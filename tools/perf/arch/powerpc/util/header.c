// SPDX-License-Identifier: GPL-2.0
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/stringify.h>
#include "header.h"
#include "metricgroup.h"
#include "evlist.h"
#include <dirent.h>
#include "pmu.h"
#include <api/fs/fs.h>

#define mfspr(rn)       ({unsigned long rval; \
			 asm volatile("mfspr %0," __stringify(rn) \
				      : "=r" (rval)); rval; })

#define SPRN_PVR        0x11F	/* Processor Version Register */
#define PVR_VER(pvr)    (((pvr) >>  16) & 0xFFFF) /* Version field */
#define PVR_REV(pvr)    (((pvr) >>   0) & 0xFFFF) /* Revison field */

#define SOCKETS_INFO_FILE_PATH "/devices/hv_24x7/interface/"

int
get_cpuid(char *buffer, size_t sz)
{
	unsigned long pvr;
	int nb;

	pvr = mfspr(SPRN_PVR);

	nb = scnprintf(buffer, sz, "%lu,%lu$", PVR_VER(pvr), PVR_REV(pvr));

	/* look for end marker to ensure the entire data fit */
	if (strchr(buffer, '$')) {
		buffer[nb-1] = '\0';
		return 0;
	}
	return ENOBUFS;
}

char *
get_cpuid_str(struct perf_pmu *pmu __maybe_unused)
{
	char *bufp;

	if (asprintf(&bufp, "%.8lx", mfspr(SPRN_PVR)) < 0)
		bufp = NULL;

	return bufp;
}

int arch_get_runtimeparam(void)
{
	int count = 0;
	DIR *dir;
	char path[PATH_MAX];
	const char *sysfs = sysfs__mountpoint();
	char filename[] = "sockets";
	FILE *file;
	char buf[16], *num;
	int data;

	if (!sysfs)
		goto out;
	snprintf(path, PATH_MAX,
		 "%s" SOCKETS_INFO_FILE_PATH, sysfs);
	dir = opendir(path);
	if (!dir)
		goto out;
	strcat(path, filename);
	file = fopen(path, "r");
	if (!file)
		goto out;

	data = fread(buf, 1, sizeof(buf), file);
	if (data == 0)
		goto out;
	count = strtol(buf, &num, 10);
out:
	if (!count)
		count = 1;
	return count;
}
