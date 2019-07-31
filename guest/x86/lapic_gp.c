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
	
	asm volatile("cpuid"
		:"=&a"(eax), "=&d"(edx), "=&b"(ebx), "=&c"(ecx)
		:"0"(0x1), "3"(0)
		:"memory", "cc");
	GENERIC_REPORT(!!((ecx & 0x1 << 21)), "The x2APIC is support");
	return 0;
}


void test_isr(isr_regs_t *regs) {

	// EOI: Chapter 10.8.5 Vol.3 SDM.
	atomic_inc(&test_isr_cnt);
	GENERIC_DEBUG("The APIC Timer ISR is called +acc %u", atomic_read(&test_isr_cnt));

	eoi();
}

#define GP3
int main(void)
{
	int ret;
	setup_idt();

	lapic_pre_condition();

	//x2APIC Mode

#ifdef GP1
	unsigned regval;
	regval = apic_read(APIC_TMR);
	apic_write(APIC_TMR,regval);
	GENERIC_REPORT( 1, 
		"should have  GP, APIC_TMR is read-only register!");
#else 
  #ifdef  GP2
	unsigned regval;
	apic_write(APIC_EOI, 0);
	regval = apic_read(APIC_EOI);
	GENERIC_REPORT( 1, 
		"should have  GP, APIC_EOI(%x) is write-only register!", regval);
  #else
    #ifdef  GP3
	unsigned regval;
	regval = apic_read(APIC_ID);
	apic_write(APIC_ID, 0x1);
	GENERIC_REPORT( 1, 
		"should have  GP, APIC_ID(%x) is write-only register!", regval);
    #endif
  #endif
#endif
	ret = report_summary();
	return ret;
}
