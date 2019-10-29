# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux kernel.
#

# Disable clang warning for using setjmp without setjmp.h header
CFLAGS_crash.o		+= $(call cc-disable-warning, builtin-requires-header)

obj-y				+= machine.o crash.o machine_$(BITS).o

obj-$(CONFIG_PPC32)		+= relocate_32.o

obj-$(CONFIG_KEXEC_FILE)	+= machine_file_$(BITS).o elf_$(BITS).o

ifdef CONFIG_HAVE_IMA_KEXEC
ifdef CONFIG_IMA
obj-y				+= ima.o
endif
endif


# Disable GCOV, KCOV & sanitizers in odd or sensitive code
GCOV_PROFILE_machine_$(BITS).o := n
KCOV_INSTRUMENT_machine_$(BITS).o := n
UBSAN_SANITIZE_machine_$(BITS).o := n
