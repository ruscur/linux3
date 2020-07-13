// SPDX-License-Identifier: GPL-2.0-only
/*
 * purgatory: Runs between two kernels
 *
 * Copyright 2020, Hari Bathini, IBM Corporation.
 */

#include <asm/purgatory.h>
#include <asm/crashdump-ppc64.h>

extern unsigned long backup_start;

static void *__memcpy(void *dest, const void *src, unsigned long n)
{
	unsigned long i;
	unsigned char *d;
	const unsigned char *s;

	d = dest;
	s = src;
	for (i = 0; i < n; i++)
		d[i] = s[i];

	return dest;
}

void purgatory(void)
{
	void *dest, *src;

	src = (void *)BACKUP_SRC_START;
	if (backup_start) {
		dest = (void *)backup_start;
		__memcpy(dest, src, BACKUP_SRC_SIZE);
	}
}
