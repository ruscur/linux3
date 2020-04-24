# SPDX-License-Identifier: GPL-2.0
# The loops are all 64-bit code
GIT_VERSION = $(shell git describe --always --long --dirty || echo "unknown")
CFLAGS += -DGIT_VERSION='"$(GIT_VERSION)"' -I$(CURDIR) -I$(CURDIR)/../include

EXTRA_SOURCES := ../harness.c

build_32bit = $(shell if ($(CC) $(CFLAGS) -m32 -o /dev/null memcmp.c >/dev/null 2>&1) then echo "1"; fi)

ifneq ($(build_32bit),1)
TEST_GEN_PROGS := memcmp_64 strlen
TEST_GEN_FILES := memcmp.o memcmp_64.o memcmp_64
MEMCMP := $(OUTPUT)/memcmp.o
MEMCMP_64 := $(OUTPUT)/memcmp_64.o
HARNESS :=  $(OUTPUT)/../harness.o
CFLAGS += -m64 -maltivec

OVERRIDE_TARGETS := 1
include ../../lib.mk

$(OUTPUT)/memcmp_64: $(MEMCMP_64) $(MEMCMP) $(HARNESS)
	$(CC) $(CFLAGS) memcmp.o memcmp_64.o ../harness.o -o memcmp_64

$(MEMCMP_64): memcmp_64.S
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -o memcmp_64.o -c memcmp_64.S

$(MEMCMP): memcmp.c
	$(CC) $(CFLAGS) -o memcmp.o -c memcmp.c

$(HARNESS): $(EXTRA_SOURCES)
	$(CC) $(CFLAGS) -DGIT_VERSION='"$(GIT_VERSION)"' -o ../harness.o -c $(EXTRA_SOURCES)
else
$(OUTPUT)/memcmp_32: memcmp.c
$(OUTPUT)/memcmp_32: CFLAGS += -m32

TEST_GEN_PROGS += memcmp_32
endif

ifneq ($(build_32bit),1)
$(OUTPUT)/strlen: string.c
else
$(OUTPUT)/strlen_32: strlen.c
$(OUTPUT)/strlen_32: CFLAGS += -m32

TEST_GEN_PROGS += strlen_32
endif

ASFLAGS = $(CFLAGS)

top_srcdir = ../../../../..
ifeq ($(build_32bit),1)
include ../../lib.mk
endif

$(TEST_GEN_PROGS): $(EXTRA_SOURCES)
