/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __GENERIC_IO_H
#define __GENERIC_IO_H

#include <linux/linkage.h>
#include <asm/byteorder.h>

/*
 * These are the "generic" interfaces for doing new-style
 * memory-mapped or PIO accesses. Architectures may do
 * their own arch-optimized versions, these just act as
 * wrappers around the old-style IO register access functions:
 * read[bwl]/write[bwl]/in[bwl]/out[bwl]
 *
 * Don't include this directly, include it from <asm/io.h>.
 */

/*
 * Read/write from/to an (offsettable) iomem cookie. It might be a PIO
 * access or a MMIO access, these functions don't care. The info is
 * encoded in the hardware mapping set up by the mapping functions
 * (or the cookie itself, depending on implementation and hw).
 *
 * The generic routines just encode the PIO/MMIO as part of the
 * cookie, and coldly assume that the MMIO IO mappings are not
 * in the low address range. Architectures for which this is not
 * true can't use this generic implementation.
 */
#ifndef ioread8
#define ioread8 ioread8
extern unsigned int ioread8(void __iomem *);
#endif
#ifndef ioread16
#define ioread16 ioread16
extern unsigned int ioread16(void __iomem *);
#endif
#ifndef ioread16be
#define ioread16be ioread16be
extern unsigned int ioread16be(void __iomem *);
#endif
#ifndef ioread32
#define ioread32 ioread32
extern unsigned int ioread32(void __iomem *);
#endif
#ifndef ioread32be
#define ioread32be ioread32be
extern unsigned int ioread32be(void __iomem *);
#endif
#ifdef CONFIG_64BIT
#ifndef ioread64
#define ioread64 ioread64
extern u64 ioread64(void __iomem *);
#endif
#ifndef ioread64be
#define ioread64be ioread64be
extern u64 ioread64be(void __iomem *);
#endif
#endif /* CONFIG_64BIT */

#ifdef readq
#ifndef ioread64_lo_hi
#define ioread64_lo_hi ioread64_lo_hi
extern u64 ioread64_lo_hi(void __iomem *addr);
#endif
#ifndef ioread64_hi_lo
#define ioread64_hi_lo ioread64_hi_lo
extern u64 ioread64_hi_lo(void __iomem *addr);
#endif
#ifndef ioread64be_lo_hi
#define ioread64be_lo_hi ioread64be_lo_hi
extern u64 ioread64be_lo_hi(void __iomem *addr);
#endif
#ifndef ioread64be_hi_lo
#define ioread64be_hi_lo ioread64be_hi_lo
extern u64 ioread64be_hi_lo(void __iomem *addr);
#endif
#endif /* readq */

#ifndef iowrite8
#define iowrite8 iowrite8
extern void iowrite8(u8, void __iomem *);
#endif
#ifndef iowrite16
#define iowrite16 iowrite16
extern void iowrite16(u16, void __iomem *);
#endif
#ifndef iowrite16be
#define iowrite16be iowrite16be
extern void iowrite16be(u16, void __iomem *);
#endif
#ifndef iowrite32
#define iowrite32 iowrite32
extern void iowrite32(u32, void __iomem *);
#endif
#ifndef iowrite32be
#define iowrite32be iowrite32be
extern void iowrite32be(u32, void __iomem *);
#endif
#ifdef CONFIG_64BIT
#ifndef iowrite64
#define iowrite64 iowrite64
extern void iowrite64(u64, void __iomem *);
#endif
#ifndef iowrite64be
#define iowrite64be iowrite64be
extern void iowrite64be(u64, void __iomem *);
#endif
#endif /* CONFIG_64BIT */

#ifdef writeq
#ifndef iowrite64_lo_hi
#define iowrite64_lo_hi iowrite64_lo_hi
extern void iowrite64_lo_hi(u64 val, void __iomem *addr);
#endif
#ifndef iowrite64_hi_lo
#define iowrite64_hi_lo iowrite64_hi_lo
extern void iowrite64_hi_lo(u64 val, void __iomem *addr);
#endif
#ifndef iowrite64be_lo_hi
#define iowrite64be_lo_hi iowrite64be_lo_hi
extern void iowrite64be_lo_hi(u64 val, void __iomem *addr);
#endif
#ifndef iowrite64be_hi_lo
#define iowrite64be_hi_lo iowrite64be_hi_lo
extern void iowrite64be_hi_lo(u64 val, void __iomem *addr);
#endif
#endif /* writeq */

/*
 * "string" versions of the above. Note that they
 * use native byte ordering for the accesses (on
 * the assumption that IO and memory agree on a
 * byte order, and CPU byteorder is irrelevant).
 *
 * They do _not_ update the port address. If you
 * want MMIO that copies stuff laid out in MMIO
 * memory across multiple ports, use "memcpy_toio()"
 * and friends.
 */
#ifndef ioread8_rep
#define ioread8_rep ioread8_rep
extern void ioread8_rep(void __iomem *port, void *buf, unsigned long count);
#endif
#ifndef ioread16_rep
#define ioread16_rep ioread16_rep
extern void ioread16_rep(void __iomem *port, void *buf, unsigned long count);
#endif
#ifndef ioread32_rep
#define ioread32_rep ioread32_rep
extern void ioread32_rep(void __iomem *port, void *buf, unsigned long count);
#endif

#ifndef iowrite8_rep
#define iowrite8_rep iowrite8_rep
extern void iowrite8_rep(void __iomem *port, const void *buf, unsigned long count);
#endif
#ifndef iowrite16_rep
#define iowrite16_rep iowrite16_rep
extern void iowrite16_rep(void __iomem *port, const void *buf, unsigned long count);
#endif
#ifndef iowrite32_rep
#define iowrite32_rep iowrite32_rep
extern void iowrite32_rep(void __iomem *port, const void *buf, unsigned long count);
#endif

#ifdef CONFIG_HAS_IOPORT_MAP
/* Create a virtual mapping cookie for an IO port range */
#ifndef ioport_map
#define ioport_map ioport_map
extern void __iomem *ioport_map(unsigned long port, unsigned int nr);
#endif
#ifndef ioport_unmap
#define ioport_unmap ioport_unmap
extern void ioport_unmap(void __iomem *);
#endif
#endif /* CONFIG_HAS_IOPORT_MAP */

#ifndef ARCH_HAS_IOREMAP_WC
#define ioremap_wc ioremap_nocache
#endif

#ifndef ARCH_HAS_IOREMAP_WT
#define ioremap_wt ioremap_nocache
#endif

#include <asm-generic/pci_iomap.h>

#endif
