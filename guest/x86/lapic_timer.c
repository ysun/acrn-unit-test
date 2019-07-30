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

static atomic_t timer_isr_cnt = {0};
void apic_timer_isr(isr_regs_t *regs) {

        // EOI: Chapter 10.8.5 Vol.3 SDM.
        atomic_inc(&timer_isr_cnt);
        GENERIC_DEBUG("The APIC Timer ISR is called +acc %u", atomic_read(&timer_isr_cnt));
        eoi();
}

int main(void)
{
	int ret;
	unsigned regval;
	setup_idt();

	lapic_pre_condition();

	// Register the ISR for Spurious Interrut

#define LAPIC_LVTT_VECTOR_MASK 0x0FF
        irq_disable();
        handle_irq(LAPIC_TEST_VEC, apic_timer_isr);
        irq_enable();

        apic_write(APIC_TMICT, 0);
        wrmsr(MSR_IA32_TSCDEADLINE, 0);

        regval = apic_read(APIC_TMICT);
        GENERIC_REPORT(regval == 0, "Stop the APIC Timer - Initial Count Register");

        regval = apic_read(APIC_TMCCT);
        GENERIC_REPORT(regval == 0, "Stop the APIC Timer - Current Count Register");

        GENERIC_REPORT(rdmsr(MSR_IA32_TSCDEADLINE) == 0, "Stop the APIC Timer - TSC mode!");

        regval = apic_read(APIC_LVTT);
        GENERIC_REPORT( (regval & APIC_LVT_TIMER_MASK) != APIC_LVT_TIMER_MASK, "The APIC LVT Timer Mode Configuration");

        // Periodic Mode
        regval &= ~APIC_LVT_TIMER_MASK;
        regval |= APIC_LVT_TIMER_PERIODIC;

        // Mask
        regval &= ~APIC_LVT_MASKED;

        // APIC Timer Vector
        regval &= ~LAPIC_LVTT_VECTOR_MASK;
        apic_write(APIC_LVTT, regval | LAPIC_TEST_VEC);

        regval = apic_read(APIC_LVTT);
        GENERIC_REPORT( (regval & APIC_LVT_TIMER_MASK) == APIC_LVT_TIMER_PERIODIC,
		"Switch The APIC LVT Timer Periodic Mode");

#define LAPIC_TIMER_INITIAL_VALUE 100
        GENERIC_REPORT(atomic_read(&timer_isr_cnt) == 0, "Trigger Periodic timer Once");
        apic_write(APIC_TMICT, LAPIC_TIMER_INITIAL_VALUE);

        // volatile unsigned delay = LAPIC_TIMER_INITIAL_VALUE * 1;
        // while(--delay)
        // nop();

        do { nop(); } while(atomic_read(&timer_isr_cnt) <= 1);
        irq_disable();

        GENERIC_REPORT(atomic_read(&timer_isr_cnt) > 1,
		"Start Periodic timer");
        GENERIC_REPORT(rdmsr(MSR_IA32_TSCDEADLINE) == 0,
		"Stoped Periodic timer with MSR_IA32_TSCDEADLINE shoule be 0");

        GENERIC_REPORT(apic_read(APIC_TMCCT) != 0,
		"Stoped Periodic timer with APIC Timer Current Count Register almostly not be 0");
        GENERIC_REPORT(apic_read(APIC_TMICT) == LAPIC_TIMER_INITIAL_VALUE,
                "Stoped Periodic timer with APIC Timer Initial Count Register shoule be %u",
		LAPIC_TIMER_INITIAL_VALUE);

        apic_write(APIC_TMICT, 0);

        irq_enable();

        GENERIC_REPORT(apic_read(APIC_TMICT) == 0, "Stoped Periodic timer with APIC Timer Initial Count Register shoule be 0");
//////////////////////////////////////////////////////////////////////////////
	GENERIC_DEBUG("=================================");
        apic_write(APIC_TMICT, 0);
        wrmsr(MSR_IA32_TSCDEADLINE, 0);

        regval = apic_read(APIC_TMICT);
        GENERIC_REPORT(regval == 0, "Stop the APIC Timer - Initial Count Register");

        regval = apic_read(APIC_TMCCT);
        GENERIC_REPORT(regval == 0, "Stop the APIC Timer - Current Count Register");

	mb();
	//One-shot Mode
        regval &= ~APIC_LVT_TIMER_MASK;
        regval |= APIC_LVT_TIMER_ONESHOT;

        // Mask
        regval &= ~APIC_LVT_MASKED;

        // APIC Timer Vector
        regval &= ~LAPIC_LVTT_VECTOR_MASK;
        apic_write(APIC_LVTT, regval | LAPIC_TEST_VEC);

        regval = apic_read(APIC_LVTT);
        GENERIC_REPORT( (regval & APIC_LVT_TIMER_MASK) == APIC_LVT_TIMER_ONESHOT,
		"Switch The APIC LVT Timer One-shot Mode");

	atomic_set(&timer_isr_cnt, 0);
        apic_write(APIC_TMICT, LAPIC_TIMER_INITIAL_VALUE);

        irq_disable();

        GENERIC_REPORT(atomic_read(&timer_isr_cnt) >= 1,
		"Start One-shot timer");
        GENERIC_REPORT(rdmsr(MSR_IA32_TSCDEADLINE) == 0,
		"Stoped One-shot timer with MSR_IA32_TSCDEADLINE shoule be 0");

        GENERIC_REPORT(apic_read(APIC_TMCCT) == 0,
		"Stoped One-timeer timer with APIC Timer Current Count Register always be 0");
        GENERIC_REPORT(apic_read(APIC_TMICT) == LAPIC_TIMER_INITIAL_VALUE,
                "Stoped One-timer with APIC Timer Initial Count Register shoule be %u",
		LAPIC_TIMER_INITIAL_VALUE);

        apic_write(APIC_TMICT, 0);

        irq_enable();

        GENERIC_REPORT(apic_read(APIC_TMICT) == 0, "Stoped Periodic timer with APIC Timer Initial Count Register shoule be 0");

///////////////////////////////////////////////////////////////
	GENERIC_DEBUG("=================================");
	atomic_set(&timer_isr_cnt, 0);

	apic_write(APIC_TMICT, 0);
	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	
	regval = apic_read(APIC_TMICT);
	GENERIC_REPORT(regval == 0, "Stop the APIC Timer - Initial Count Register");
	regval = apic_read(APIC_TMCCT);
	GENERIC_REPORT(regval == 0, "Stop the APIC Timer - Current Count Register");
	GENERIC_REPORT(rdmsr(MSR_IA32_TSCDEADLINE) == 0,
		"Stop the APIC Timer - TSC deadline timer");
	
	regval = apic_read(APIC_LVTT);
	GENERIC_REPORT( (regval & APIC_LVT_TIMER_MASK) != APIC_LVT_TIMER_MASK, "The APIC LVT Timernfiguration");
	
	// TSC Deadline Mode
	regval &= ~APIC_LVT_TIMER_MASK;
	regval |= APIC_LVT_TIMER_TSCDEADLINE;
	
	// Mask
	regval &= ~APIC_LVT_MASKED;
	
	// APIC Timer Vector
	regval &= ~LAPIC_LVTT_VECTOR_MASK;
	apic_write(APIC_LVTT, regval | LAPIC_TEST_VEC);
	
	regval = apic_read(APIC_LVTT);
	GENERIC_REPORT( (regval & APIC_LVT_TIMER_MASK) == APIC_LVT_TIMER_TSCDEADLINE,
		"Switch to APIC LVT Timer TSC Deadline Mode");
	
	GENERIC_REPORT(atomic_read(&timer_isr_cnt) == 0,
		"Trigger TSC deadline timer Once");
	wrmsr(MSR_IA32_TSCDEADLINE, rdmsr(MSR_IA32_TSC));
	
	GENERIC_REPORT(atomic_read(&timer_isr_cnt) == 1, "Start TSC deadline timer");
	GENERIC_REPORT(rdmsr(MSR_IA32_TSCDEADLINE) == 0, "Stoped TSC deadline timer");

	ret = report_summary();
	return ret;
}
