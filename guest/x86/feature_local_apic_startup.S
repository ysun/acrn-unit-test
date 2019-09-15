#include "apic-defs.h"
#include "msr.h"

#define APIC_RESET_BASE 0xfee00000
#define LAPIC_APIC_STRUCT(reg)  (((reg) >> 2) + 0)
#ifndef APIC_MSR_CR8
#define APIC_MSR_CR8            0x400
#endif
#ifndef APIC_MSR_CR81
#define APIC_MSR_CR81           0x410
#endif
#ifndef APIC_MSR_IA32_APICBASE
#define APIC_MSR_IA32_APICBASE  0x420
#endif
#ifndef APIC_MSR_IA32_APICBASE1
#define APIC_MSR_IA32_APICBASE1 0x430
#endif
#ifndef APIC_MSR_IA32_TSCDEADLINE
#define APIC_MSR_IA32_TSCDEADLINE       0x440
#endif
#ifndef APIC_MSR_IA32_TSCDEADLINE1
#define APIC_MSR_IA32_TSCDEADLINE1      0x450
#endif
#ifndef APIC_LVTCMCI
#define APIC_LVTCMCI 0x2f0
#endif
#define APIC_RESET_BASE 0xfee00000

#ifndef LAPIC_INIT_BP_BASE_ADDR
#define LAPIC_INIT_BP_BASE_ADDR 0x8000
#endif
#ifndef LAPIC_INIT_AP_BASE_ADDR
#define LAPIC_INIT_AP_BASE_ADDR 0x8800
#endif
#ifndef LAPIC_INIT_APIC_SIZE
#define LAPIC_INIT_APIC_SIZE	0x800
#endif

#ifndef LAPIC_PRIVATE_MEM_ADDR
#define LAPIC_PRIVATE_MEM_ADDR  0x8000UL
#endif
#ifndef LAPIC_PRIVATE_SIZE
#define LAPIC_PRIVATE_SIZE      0x800UL
#endif

#ifndef LAPIC_IRR_INDEX
#define LAPIC_IRR_INDEX(idx)    ((idx) << 4)
#endif
#ifndef LAPIC_ISR_INDEX
#define LAPIC_ISR_INDEX(idx)    ((idx) << 4)
#endif
#ifndef LAPIC_TMR_INDEX
#define LAPIC_TMR_INDEX(idx)    ((idx) << 4)
#endif

        movl $LAPIC_INIT_BP_BASE_ADDR, %ecx

	mov %edx, %esi
	mov %ecx, %edi
        movl $MSR_IA32_APICBASE, %ecx
        rdmsr
	mov %edi, %ecx
        movl %eax, LAPIC_APIC_STRUCT(APIC_MSR_IA32_APICBASE) (%ecx)
        movl %edx, LAPIC_APIC_STRUCT(APIC_MSR_IA32_APICBASE1) (%ecx)

	mov %ecx, %edi
        movl $MSR_IA32_TSCDEADLINE, %ecx
        rdmsr
	mov %edi, %ecx
        movl %eax, LAPIC_APIC_STRUCT(APIC_MSR_IA32_TSCDEADLINE) (%ecx)
        movl %edx, LAPIC_APIC_STRUCT(APIC_MSR_IA32_TSCDEADLINE1) (%ecx)
	mov %esi, %edx

        mov (APIC_RESET_BASE + APIC_ID), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ID) (%ecx)

        mov (APIC_RESET_BASE + APIC_LVR), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_LVR) (%ecx)

        mov (APIC_RESET_BASE + APIC_TASKPRI), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TASKPRI) (%ecx)

        mov (APIC_RESET_BASE + APIC_ARBPRI), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ARBPRI) (%ecx)

        mov (APIC_RESET_BASE + APIC_PROCPRI), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_PROCPRI) (%ecx)

        mov (APIC_RESET_BASE + APIC_EOI), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_EOI) (%ecx)

        /* mov (APIC_RESET_BASE + APIC_RRR), %eax */
        /* movl %eax, LAPIC_APIC_STRUCT(APIC_RRR) (%ecx) */

        mov (APIC_RESET_BASE + APIC_LDR), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_LDR) (%ecx)

        /* mov (APIC_RESET_BASE + APIC_DFR), %eax */
        /* movl %eax, LAPIC_APIC_STRUCT(APIC_DFR) (%ecx) */

        mov (APIC_RESET_BASE + APIC_SPIV), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_SPIV) (%ecx)

        mov (APIC_RESET_BASE + APIC_ISR + LAPIC_ISR_INDEX(0)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(0)) (%ecx)

        mov (APIC_RESET_BASE + APIC_ISR + LAPIC_ISR_INDEX(1)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(1)) (%ecx)

        mov (APIC_RESET_BASE + APIC_ISR + LAPIC_ISR_INDEX(2)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(2)) (%ecx)

        mov (APIC_RESET_BASE + APIC_ISR + LAPIC_ISR_INDEX(3)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(3)) (%ecx)

        mov (APIC_RESET_BASE + APIC_ISR + LAPIC_ISR_INDEX(4)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(4)) (%ecx)

        mov (APIC_RESET_BASE + APIC_ISR + LAPIC_ISR_INDEX(5)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(5)) (%ecx)

        mov (APIC_RESET_BASE + APIC_ISR + LAPIC_ISR_INDEX(6)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(6)) (%ecx)

        mov (APIC_RESET_BASE + APIC_ISR + LAPIC_ISR_INDEX(7)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(7)) (%ecx)

        mov (APIC_RESET_BASE + APIC_TMR + LAPIC_TMR_INDEX(0)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(0)) (%ecx)

        mov (APIC_RESET_BASE + APIC_TMR + LAPIC_TMR_INDEX(1)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(1)) (%ecx)

        mov (APIC_RESET_BASE + APIC_TMR + LAPIC_TMR_INDEX(2)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(2)) (%ecx)

        mov (APIC_RESET_BASE + APIC_TMR + LAPIC_TMR_INDEX(3)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(3)) (%ecx)

        mov (APIC_RESET_BASE + APIC_TMR + LAPIC_TMR_INDEX(4)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(4)) (%ecx)

        mov (APIC_RESET_BASE + APIC_TMR + LAPIC_TMR_INDEX(5)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(5)) (%ecx)

        mov (APIC_RESET_BASE + APIC_TMR + LAPIC_TMR_INDEX(6)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(6)) (%ecx)

        mov (APIC_RESET_BASE + APIC_TMR + LAPIC_TMR_INDEX(7)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(7)) (%ecx)

        mov (APIC_RESET_BASE + APIC_IRR + LAPIC_IRR_INDEX(0)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(0)) (%ecx)

        mov (APIC_RESET_BASE + APIC_IRR + LAPIC_IRR_INDEX(1)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(1)) (%ecx)

        mov (APIC_RESET_BASE + APIC_IRR + LAPIC_IRR_INDEX(2)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(2)) (%ecx)

        mov (APIC_RESET_BASE + APIC_IRR + LAPIC_IRR_INDEX(3)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(3)) (%ecx)

        mov (APIC_RESET_BASE + APIC_IRR + LAPIC_IRR_INDEX(4)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(4)) (%ecx)

        mov (APIC_RESET_BASE + APIC_IRR + LAPIC_IRR_INDEX(5)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(5)) (%ecx)

        mov (APIC_RESET_BASE + APIC_IRR + LAPIC_IRR_INDEX(6)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(6)) (%ecx)

        mov (APIC_RESET_BASE + APIC_IRR + LAPIC_IRR_INDEX(7)), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(7)) (%ecx)

        mov (APIC_RESET_BASE + APIC_ESR), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ESR) (%ecx)

        mov (APIC_RESET_BASE + APIC_LVTCMCI), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_LVTCMCI) (%ecx)

        mov (APIC_RESET_BASE + APIC_ICR), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ICR) (%ecx)

        mov (APIC_RESET_BASE + APIC_ICR2), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_ICR2) (%ecx)

        mov (APIC_RESET_BASE + APIC_LVTT), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_LVTT) (%ecx)

        mov (APIC_RESET_BASE + APIC_LVTTHMR), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_LVTTHMR) (%ecx)

        mov (APIC_RESET_BASE + APIC_LVTPC), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_LVTPC) (%ecx)

        mov (APIC_RESET_BASE + APIC_LVT0), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_LVT0) (%ecx)

        mov (APIC_RESET_BASE + APIC_LVT1), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_LVT1) (%ecx)

        mov (APIC_RESET_BASE + APIC_LVTERR), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_LVTERR) (%ecx)

        mov (APIC_RESET_BASE + APIC_TMICT), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TMICT) (%ecx)

        mov (APIC_RESET_BASE + APIC_TMCCT), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TMCCT) (%ecx)

        mov (APIC_RESET_BASE + APIC_TDCR), %eax
        movl %eax, LAPIC_APIC_STRUCT(APIC_TDCR) (%ecx)

        /* mov (APIC_RESET_BASE + APIC_APIC_SELF_IPI), %eax */
        /* movl %eax, LAPIC_APIC_STRUCT(APIC_APIC_SELF_IPI) (%ecx) */
