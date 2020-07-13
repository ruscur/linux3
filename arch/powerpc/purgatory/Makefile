# SPDX-License-Identifier: GPL-2.0

KASAN_SANITIZE := n

purgatory-y := purgatory_$(BITS).o trampoline_$(BITS).o

targets += $(purgatory-y)
PURGATORY_OBJS = $(addprefix $(obj)/,$(purgatory-y))

LDFLAGS_purgatory.ro := -e purgatory_start -r --no-undefined
targets += purgatory.ro

PURGATORY_CFLAGS_REMOVE :=

# Default KBUILD_CFLAGS can have -pg option set when FUNCTION_TRACE is
# enabled leaving some undefined symbols like _mcount in purgatory.
ifdef CONFIG_FUNCTION_TRACER
PURGATORY_CFLAGS_REMOVE			+= $(CC_FLAGS_FTRACE)
endif

ifdef CONFIG_STACKPROTECTOR
PURGATORY_CFLAGS_REMOVE		+= -fstack-protector
endif

ifdef CONFIG_STACKPROTECTOR_STRONG
PURGATORY_CFLAGS_REMOVE		+= -fstack-protector-strong
endif

CFLAGS_REMOVE_purgatory_$(BITS).o	+= $(PURGATORY_CFLAGS_REMOVE)

$(obj)/purgatory.ro: $(PURGATORY_OBJS) FORCE
		$(call if_changed,ld)

targets += kexec-purgatory.c

quiet_cmd_bin2c = BIN2C   $@
      cmd_bin2c = $(objtree)/scripts/bin2c kexec_purgatory < $< > $@

$(obj)/kexec-purgatory.c: $(obj)/purgatory.ro FORCE
	$(call if_changed,bin2c)

obj-y	+= kexec-purgatory.o
