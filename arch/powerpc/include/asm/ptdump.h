/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_POWERPC_PTDUMP_H
#define _ASM_POWERPC_PTDUMP_H

#ifndef __ASSEMBLY__

#ifdef CONFIG_PPC_DEBUG_WX
void ptdump_check_wx(void);
#else
static inline void ptdump_check_wx(void) { }
#endif

#endif /* __ASSEMBLY__ */

#endif /* _ASM_POWERPC_PTDUMP_H */
