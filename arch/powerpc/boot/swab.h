/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PPC_BOOT_SWAB_H_
#define _PPC_BOOT_SWAB_H_

static inline u16 swab16(u16 x)
{
	return  ((x & (u16)0x00ffU) << 8) |
		((x & (u16)0xff00U) >> 8);
}

static inline u32 swab32(u32 x)
{
	return  ((x & (u32)0x000000ffUL) << 24) |
		((x & (u32)0x0000ff00UL) <<  8) |
		((x & (u32)0x00ff0000UL) >>  8) |
		((x & (u32)0xff000000UL) >> 24);
}

static inline u64 swab64(u64 x)
{
	return  (u64)((x & (u64)0x00000000000000ffULL) << 56) |
		(u64)((x & (u64)0x000000000000ff00ULL) << 40) |
		(u64)((x & (u64)0x0000000000ff0000ULL) << 24) |
		(u64)((x & (u64)0x00000000ff000000ULL) <<  8) |
		(u64)((x & (u64)0x000000ff00000000ULL) >>  8) |
		(u64)((x & (u64)0x0000ff0000000000ULL) >> 24) |
		(u64)((x & (u64)0x00ff000000000000ULL) >> 40) |
		(u64)((x & (u64)0xff00000000000000ULL) >> 56);
}

#ifdef __LITTLE_ENDIAN__
#define cpu_to_be16(x) swab16(x)
#define be16_to_cpu(x) swab16(x)
#define cpu_to_be32(x) swab32(x)
#define be32_to_cpu(x) swab32(x)
#define cpu_to_be64(x) swab64(x)
#define be64_to_cpu(x) swab64(x)
#else
#define cpu_to_be16(x) (x)
#define be16_to_cpu(x) (x)
#define cpu_to_be32(x) (x)
#define be32_to_cpu(x) (x)
#define cpu_to_be64(x) (x)
#define be64_to_cpu(x) (x)
#endif

#endif /* _PPC_BOOT_SWAB_H_ */
