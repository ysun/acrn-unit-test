/*
 * Copyright (c) 2019 Intel Corporation. All rights reserved.
 * Test mode: 64-bit
 */

#include "libcflat.h"
#include "apic.h"
#include "vm.h"
#include "smp.h"
#include "desc.h"
#include "isr.h"
#include "msr.h"
#include "atomic.h"

#include "./64/feature_local_apic_fn.c"


int main(int ac, char **av)
{
        (void) ac;
        (void) av;

        /* setup_vm(); */
        /* smp_init(); */
        setup_idt();

	/* API to select one or all case to run */
	printf("!!!!!ysun\n");

	local_apic_rqmid_27696_apic_capability_001();

	return report_summary();
}
