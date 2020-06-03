/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LZO_CONFIG_H__
#define __LZO_CONFIG_H__

#include "types.h"
#include "swab.h"

#ifdef __LITTLE_ENDIAN__
static inline u32 be32_to_cpup(const u32 *p)
{
	return swab32(*(u32 *)p);
}
static inline u16 be16_to_cpup(const u16 *p)
{
	return swab16(*(u16 *)p);
}
static inline u16 le16_to_cpup(const u16 *p)
{
	return *p;
}
#else
static inline u32 be32_to_cpup(const u32 *p)
{
	return *p;
}
static inline u16 be16_to_cpup(const u16 *p)
{
	return *p;
}
static inline u16 le16_to_cpup(const u16 *p)
{
	return swab16(*(u16 *)p);
}
#endif

static inline uint32_t get_unaligned_be32(const void *p)
{
	return be32_to_cpup(p);
}

static inline uint32_t get_unaligned_be16(const void *p)
{
	return be16_to_cpup(p);
}

static inline uint32_t get_unaligned_le16(const void *p)
{
	return le16_to_cpup(p);
}

#define get_unaligned(ptr) (*(ptr))
#define put_unaligned(val, ptr) do { *(ptr) = val; } while (0)

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

#endif
