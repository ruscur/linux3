# SPDX-License-Identifier: GPL-2.0
# Makefile for vm selftests
uname_M := $(shell uname -m 2>/dev/null || echo not)
ARCH ?= $(shell echo $(uname_M) | sed -e 's/aarch64.*/arm64/')

CFLAGS = -Wall -I ../../../../usr/include $(EXTRA_CFLAGS)
LDLIBS = -lrt
TEST_GEN_FILES = compaction_test
TEST_GEN_FILES += gup_benchmark
TEST_GEN_FILES += hugepage-mmap
TEST_GEN_FILES += hugepage-shm
TEST_GEN_FILES += map_hugetlb
TEST_GEN_FILES += map_fixed_noreplace
TEST_GEN_FILES += map_populate
TEST_GEN_FILES += mlock-random-test
TEST_GEN_FILES += mlock2-tests
TEST_GEN_FILES += on-fault-limit
TEST_GEN_FILES += thuge-gen
TEST_GEN_FILES += transhuge-stress
TEST_GEN_FILES += userfaultfd

ifeq ($(ARCH), x86_64)
CAN_BUILD_I386 := $(shell ./../x86/check_cc.sh $(CC) ../x86/trivial_32bit_program.c -m32)
CAN_BUILD_X86_64 := $(shell ./../x86/check_cc.sh $(CC) ../x86/trivial_64bit_program.c)
CAN_BUILD_WITH_NOPIE := $(shell ./../x86/check_cc.sh $(CC) ../x86/trivial_program.c -no-pie)

TARGETS := protection_keys
BINARIES_32 := $(TARGETS:%=%_32)
BINARIES_64 := $(TARGETS:%=%_64)

.PHONY: $(TARGETS)

ifeq ($(CAN_BUILD_WITH_NOPIE),1)
CFLAGS += -no-pie
endif

ifeq ($(CAN_BUILD_I386),1)
TEST_GEN_FILES += $(BINARIES_32)
$(TARGETS): $(BINARIES_32)
$(BINARIES_32): %_32: %.c
	$(CC) -m32 -o $@ $(CFLAGS) $(EXTRA_CFLAGS) $^ -lrt -ldl -lm
endif

ifeq ($(CAN_BUILD_X86_64),1)
TEST_GEN_FILES += $(BINARIES_64)
$(TARGETS): $(BINARIES_64)
$(BINARIES_64): %_64: %.c
	$(CC) -m64 -o $@ $(CFLAGS) $(EXTRA_CFLAGS) $^ -lrt -ldl
endif

# x86_64 users should be encouraged to install 32-bit libraries
ifeq ($(CAN_BUILD_I386)$(CAN_BUILD_X86_64),01)
$(TARGETS): warn_32bit_failure

warn_32bit_failure:
	@echo "Warning: you seem to have a broken 32-bit build" 2>&1;		\
	echo "environment.  This will reduce test coverage of 64-bit" 2>&1;	\
	echo "kernels.  If you are using a Debian-like distribution," 2>&1;	\
	echo "try:"; 2>&1;							\
	echo "";								\
	echo "  apt-get install gcc-multilib libc6-i386 libc6-dev-i386";	\
	echo "";								\
	echo "If you are using a Fedora-like distribution, try:";		\
	echo "";								\
	echo "  yum install glibc-devel.*i686";					\
	exit 0;
endif
else
TEST_GEN_FILES += protection_keys
endif

ifneq (,$(filter $(ARCH),arm64 ia64 mips64 parisc64 ppc64 riscv64 s390x sh64 sparc64 x86_64))
TEST_GEN_FILES += va_128TBswitch
TEST_GEN_FILES += virtual_address_range
endif

TEST_PROGS := run_vmtests

TEST_FILES := test_vmalloc.sh

KSFT_KHDR_INSTALL := 1
include ../lib.mk

$(OUTPUT)/userfaultfd: LDLIBS += -lpthread

$(OUTPUT)/mlock-random-test: LDLIBS += -lcap
