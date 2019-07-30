#include "libcflat.h"
#include "desc.h"
#include "apic.h"
#include "isr.h"
#include "processor.h"
#include "atomic.h"
#include "asm/barrier.h"
#include "asm/spinlock.h"

#define LAPIC_SPURIOUS_COUNT -128

static atomic_t test_isr_cnt = {0};
unsigned lapic_phyaddr_max = 0;

static inline int x2apic_mode(void) {
	int ret = rdmsr(MSR_IA32_APICBASE) & APIC_EXTD;
	return ret != 0;
}

#define GENERIC_DEBUG(fmt,arg...) do { 		\
	printf("[%s Mode]: " fmt "\n", x2apic_mode() ? "x2APIC": "xAPIC", ##arg); \
}  while(0)

#define GENERIC_REPORT(cond,fmt,arg...) do { 	\
	report(fmt, cond, ##arg); 		\
}  while(0)

#define nop() do { asm volatile ( "nop"); } while(0)

#define LAPIC_TEST_VEC		0xEF		// MUST Greater Thean 15
#define LAPIC_TEST_SPI_VEC	0xFF
#define LAPIC_VEC_MASK		0xFF

void spurious_isr(isr_regs_t *regs) {
	GENERIC_DEBUG("The Spurious ISR is called for vector = %#x", LAPIC_TEST_SPI_VEC);
}

int lapic_pre_condition(void) {
	unsigned eax, edx, ebx, ecx;

	(void) eax;
	(void) edx;
	(void) ebx;
	(void) ecx;
	// CPUID: eax = 0x0, ecx  = 0x0, THERE IS NO EXCEPTION/FALT
	asm volatile ("cpuid"
		: "=a"(eax), "=d"(edx), "=b"(ebx), "=c"(ecx)
		: "0"(0), "3"(0)
		: "memory", "cc");

	GENERIC_REPORT(1, "(Pre-condition)The CPUID is supported!");

	// MAXPHYADDR
	asm volatile ("cpuid"
		: "=a"(eax), "=d"(edx), "=b"(ebx), "=c"(ecx)
		: "0"(0x80000008), "3"(0)
		: "memory", "cc");

	if (!!(eax & 0x0FF))
		lapic_phyaddr_max = eax & 0x0FF;
	GENERIC_REPORT(1, "(Pre-condition)The MAXPHYADDR is %u!", lapic_phyaddr_max);
	
	return 0;
}


void test_isr(isr_regs_t *regs) {

	// EOI: Chapter 10.8.5 Vol.3 SDM.
	atomic_inc(&test_isr_cnt);
	GENERIC_DEBUG("The APIC Timer ISR is called +acc %u", atomic_read(&test_isr_cnt));

	eoi();
}

int main(void)
{
	int ret;
	unsigned svr = 0;
	unsigned regval;
	setup_idt();

	lapic_pre_condition();

	// Register the ISR for Spurious Interrut
	handle_irq(LAPIC_TEST_SPI_VEC, spurious_isr);
	svr = apic_read(APIC_SPIV);
	svr &= ~LAPIC_VEC_MASK;
	svr |= LAPIC_TEST_SPI_VEC;

	apic_write(APIC_SPIV, svr);

	svr = apic_read(APIC_SPIV);

	GENERIC_REPORT( (svr & LAPIC_VEC_MASK) == LAPIC_TEST_SPI_VEC, 
		"Update the APIC Spurious Interrupt Register Vector to %x", 
		svr & LAPIC_VEC_MASK);

	// ; x2APIC Mode
	// ; # 140805: x2APIC IPI Delivery in Physical Destination Mode
	// ; # 140809: x2APIC IPI Reception in Physical Destination Mode
	// ;
	// ; 5.; Triggier a Fixed IPI with Phycial Delivery Mode; Write to APIC_ICR with Physical, Fixed, Self, and Valid Vector; No exception, and The IPI trigged for 1 time
	irq_disable();
	handle_irq(LAPIC_TEST_VEC, test_isr);
	irq_enable();

	regval = LAPIC_TEST_VEC;
	regval |= APIC_DEST_PHYSICAL | APIC_DM_FIXED | APIC_DEST_SELF;
	apic_icr_write(regval, 0);
	GENERIC_REPORT(atomic_read(&test_isr_cnt) == 1, 
		"IPI Delivery In Physical Destination Mode: %d", atomic_read(&test_isr_cnt));

	regval = LAPIC_TEST_VEC;
	regval |= APIC_DEST_LOGICAL | APIC_DM_FIXED | APIC_DEST_ALLINC;
	apic_icr_write(regval, 0);
	GENERIC_REPORT(atomic_read(&test_isr_cnt) == 1 + 4,
		"IPI Delivery In Logical Destination Mode: %d", atomic_read(&test_isr_cnt));

	regval = LAPIC_TEST_VEC;
	regval |= APIC_DEST_PHYSICAL | APIC_DM_FIXED | APIC_DEST_ALLBUT;
	apic_icr_write(regval, 0);
	GENERIC_REPORT(atomic_read(&test_isr_cnt) == 5,
		"IPI Delivery In physical Destination/All but self: %d", atomic_read(&test_isr_cnt));

	regval = LAPIC_TEST_VEC;
	regval |= APIC_DEST_PHYSICAL | APIC_DM_LOWEST | APIC_DEST_SELF;
	apic_icr_write(regval, 0);
	GENERIC_REPORT(atomic_read(&test_isr_cnt) == 5,
		"IPI Delivery In a unsupport deliver mode: %d", atomic_read(&test_isr_cnt));

	ret = report_summary();
	return ret;
}
