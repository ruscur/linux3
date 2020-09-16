#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

if [ ! -e "/sys/kernel/debug/powerpc/mce_error_inject/inject_slb_multihit" ] ; then
        exit 0;
fi

echo 1 > /sys/kernel/debug/powerpc/mce_error_inject/inject_slb_multihit
exit 0
