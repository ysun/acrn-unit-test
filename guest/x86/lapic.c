/*
 * Test for x86 cache and memory instructions
 *
 * Copyright (c) 2019 Intel
 *
 * Authors:
 *  Zhongwei Liu <zhongweix.liu@intel.com>
 *  Yi Sun <yi.sun@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "libcflat.h"
#include "desc.h"
#include "apic.h"
#include "isr.h"
#include "processor.h"
#include "atomic.h"
#include "asm/barrier.h"
#include "asm/spinlock.h"

#define REG(name)	unsigned __APIC_##name
#define REG64(name)	unsigned long __APIC_##name
#define LAPIC_REG_NAME(s,name)	(s)->__APIC_##name
#define LAPIC_GET(s,name) do { (s)->__APIC_##name = apic_read(APIC_##name); } while(0)

#define BUGGY	//It will enable that cases which is failed on KVM
		//But not sure on real HW or hyperviosr

struct lapic_state_s {
	REG(reserved_000);
	REG(reserved_010);
	REG(ID);
	REG(VERSION);
	REG(reserved_040);
	REG(reserved_050);
	REG(reserved_060);
	REG(reserved_070);
	REG(TPR);
	REG(APR);
	REG(PPR);
	REG(EOI);
	REG(RRD);
	REG(LDR);
	REG(DFR);
	REG(SPIV);
	REG(ISR0);
	REG(ISR1);
	REG(ISR2);
	REG(ISR3);
	REG(ISR4);
	REG(ISR5);
	REG(ISR6);
	REG(ISR7);
	REG(TMR0);
	REG(TMR1);
	REG(TMR2);
	REG(TMR3);
	REG(TMR4);
	REG(TMR5);
	REG(TMR6);
	REG(TMR7);
	REG(IRR0);
	REG(IRR1);
	REG(IRR2);
	REG(IRR3);
	REG(IRR4);
	REG(IRR5);
	REG(IRR6);
	REG(IRR7);
	REG(ESR);
	REG(reserved_290);
	REG(reserved_2A0);
	REG(reserved_2B0);
	REG(reserved_2C0);
	REG(reserved_2D0);
	REG(reserved_2E0);
	REG(CMCI);
	REG64(ICR);
	REG(LVTT);
	REG(LVTTHSR);
	REG(LVTPC);
	REG(LVT0);
	REG(LVT1);
	REG(LVTERR);
	REG(TMICT);
	REG(TMCCT);
	REG(reserved_3A0);
	REG(reserved_3B0);
	REG(reserved_3C0);
	REG(reserved_3D0);
	REG(TDCR);
	REG(SELF_IPI);
} __attribute__((packed));
typedef struct lapic_state_s lapic_state_t;

#define GENERIC_DEBUG(fmt,arg...) 		\
	printf("[X2APIC]: " fmt "\n", ##arg);

#define GENERIC_REPORT(cond,fmt,arg...)		\
	do { 					\
		GENERIC_DEBUG(fmt, ##arg); 	\
		report(fmt, cond, ##arg); 	\
	}  while(0)

#define LAPIC_TEST_SPI_VEC	0x0FF
#define LAPIC_VEC_MASK		0x0FF

#define CHECK_REG_ALL0(name) do { \
GENERIC_REPORT(s->__APIC_##name == 0, #name " Reset State should be 0"); \
} while(0)

#define CHECK_REG_VAL(name,val) do { \
GENERIC_REPORT(s->__APIC_##name == val, #name " Reset State should be %#10x", val); \
} while(0)


static unsigned reserved[] = {
	0x0, 0x10, 0x40, 0x50, 0x60, 0x70, 0x90, 0xc0,
	APIC_DFR, APIC_ICR2, 0x310, 0x290, 0x2A0, 0x2B0,
	0x2C0, 0x2D0, 0x2E0, 0x3A0, 0x3B0, 0x3C0, 0x3D0,
	APIC_SELF_IPI
};

static unsigned wo [] = {
	APIC_EOI,
	APIC_SELF_IPI
};

static int is_wo(unsigned reg) {
	unsigned i = 0;
	for (; i<sizeof(wo)/sizeof(*wo); ++i) {
		if (reg == wo[i])
			return 1;
	}
	return 0;
}
static int is_reserved(unsigned reg) {
	unsigned i = 0;
	for (; i<sizeof(reserved)/sizeof(*reserved); ++i) {
		if (reg == reserved[i])
			return 1;
	}
	return 0;
}
void lapic_read_state(lapic_state_t *s) {
	unsigned i = 0;
	unsigned reg;
	unsigned *p = &LAPIC_REG_NAME(s, reserved_000);

	for (; i < 0x400 / 16; ++i, ++p) {
		//BUG: 0x2F0(CMCI) casue BSP reset!!
		if(i == 0x2f) continue;

		reg = i << 4;

		if (is_reserved(reg) || is_wo(reg))
			continue;

		if (reg == APIC_ICR) {
			LAPIC_REG_NAME(s, ICR) = apic_read(reg);
		} else {
			*p = apic_read(reg);
		}
	}
}

int lapic_check_reset_state(lapic_state_t *s) {
	unsigned i;
	unsigned *p;

	p = &LAPIC_REG_NAME(s, IRR0);
	for (i=0; i<8; ++i, ++p) {
		GENERIC_REPORT(*p == 0, "IRR%d Reset State should be 0", i);
	}

	p = &LAPIC_REG_NAME(s, ISR0);
	for (i=0; i<8; ++i, ++p) {
		GENERIC_REPORT(*p == 0, "ISR%d Reset State should be 0", i);
	}

	p = &LAPIC_REG_NAME(s, TMR0);
	for (i=0; i<8; ++i, ++p) {
		GENERIC_REPORT(*p == 0, "TMR%d Reset State should be 0", i);
	}

#ifdef BUGGY
	CHECK_REG_ALL0(ICR);
	CHECK_REG_ALL0(LDR);
#endif
	CHECK_REG_ALL0(TPR);
	CHECK_REG_ALL0(TMICT);
	CHECK_REG_ALL0(TMCCT);
	CHECK_REG_ALL0(TDCR);
#ifdef BUGGY
	CHECK_REG_VAL(CMCI, 0x10000);
	CHECK_REG_VAL(LVTT, 0x10000);
	CHECK_REG_VAL(LVTTHSR, 0x10000);
	CHECK_REG_VAL(LVTPC, 0x10000);
	CHECK_REG_VAL(LVT0, 0x10000);
	CHECK_REG_VAL(LVT1, 0x10000);
	CHECK_REG_VAL(LVTERR, 0x10000);
#endif
	CHECK_REG_VAL(VERSION, 0x1060015);
	GENERIC_DEBUG("The APIC ID is %#010x", LAPIC_REG_NAME(s, ID));

#ifdef BUGGY
	CHECK_REG_VAL(SPIV, 0x0FF);
#endif
	return 0;
}

void spurious_isr(isr_regs_t *regs) {
	GENERIC_DEBUG("The Spurious ISR is called for vector = %#lx", regs->regs[0]);
}

// returned 0 indicates
unsigned __LAPIC_MAXPHYADDR = 36;

int lapic_pre_condition(void) {
	unsigned eax, edx, ebx, ecx;
	unsigned svr;

	// CPUID: eax = 0x0, ecx  = 0x0, THERE IS NO EXCEPTION/FALT
	asm volatile ("cpuid"
		:"=a"(eax), "=d"(edx), "=b"(ebx), "=c"(ecx)
		:"0"(0), "3"(0)
		:"memory", "cc");

	GENERIC_REPORT(1, "The CUPID is supported!");

	// MAXPHYADDR
	asm volatile ("cpuid"
		: "=a"(eax), "=d"(edx), "=b"(ebx), "=c"(ecx)
		: "0"(0x80000008), "3"(0)
		: "memory", "cc");

	if (!!(eax & 0x0FF))
		__LAPIC_MAXPHYADDR = eax & 0x0FF;
	GENERIC_REPORT(1, "The MAXPHYADDR is %u!", __LAPIC_MAXPHYADDR);

    // local APIC/xAPIC support
    // MSR support
	asm volatile("cpuid"
		:"=&a"(eax), "=&d"(edx), "=&b"(ebx), "=&c"(ecx)
		: "0"(0x1), "3"(0)
		: "memory", "cc");
	if (! (edx & (0x1 << 9))) {
		GENERIC_REPORT(0, "The local APIC/xAPIC is not support");
		return -1;
	}
	if (! (edx & (0x1 << 5))) {
		GENERIC_REPORT(0, "The MSR is not support");
		return -1;
	}
	if (! (ecx & (0x1 << 21))) {
		GENERIC_REPORT(!!((ecx & 0x1 << 21)), "The x2APIC is support");
		return -1;
	}

	GENERIC_REPORT(1, "The MSR is support");
	GENERIC_REPORT(1, "The local APIC/xAPIC is support");
	GENERIC_REPORT(!!((ecx & 0x1 << 21)), "The x2APIC is support");

	// Register the ISR for Spurious Interrut
	handle_irq(LAPIC_TEST_SPI_VEC, spurious_isr);
	svr = apic_read(APIC_SPIV);
	svr &= ~LAPIC_VEC_MASK;
	svr |= LAPIC_TEST_SPI_VEC;
	apic_write(APIC_SPIV, svr);

	mb();

	svr = apic_read(APIC_SPIV);

	GENERIC_REPORT( (svr & LAPIC_VEC_MASK) == LAPIC_TEST_SPI_VEC,
		"Update the APIC Spurious Interrupt Register Vector to %x",
		svr & LAPIC_VEC_MASK);

	return 0;
}

lapic_state_t state = {0};
int main(void)
{
	int ret;
	setup_idt();

	int pre_condition = lapic_pre_condition();

	report("lapic init (pre condition test)", pre_condition == 0);

	lapic_read_state(&state);
	lapic_check_reset_state(&state);

	unsigned long cr8_val;
	asm volatile ("movq %%cr8, %0": "=r"(cr8_val):: "cc");

	GENERIC_REPORT(cr8_val == 0, 
		"ACRN hypervisor shall set initial Guest CR8 to 0H following INIT/Start-up");

	ret = report_summary();
	return ret;
}
