/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 IBM Corporation
 */

	.text

#define globl(x)		\
	.globl x;	\
x:

globl(code_patching_test1)
	nop
	nop
globl(end_code_patching_test1)

globl(code_patching_test1_expected)
	.long 1 << 26
	.long 0x0000000
