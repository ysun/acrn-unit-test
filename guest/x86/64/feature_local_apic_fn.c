/* common code */

#define LAPIC_REG_MASK	0x0FFFFFFFFUL
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
#define LAPIC_INIT_APIC_SIZE    0x800
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

#define LAPIC_CPUID_APIC_CAPABILITY	1
#define LAPIC_CPUID_APIC_CAP_OK		(0x1U << 9)
#define LAPIC_CPUID_APIC_CAP_X2APCI	(0x1U << 21)
#define LAPIC_TIMER_CAPABILITY          6
#define LAPIC_TIMER_CAPABILITY_ARAT     (0x1U << 2)

static inline int lapic_is_in_safety_mode(void)
{
	report("%s - %s", 0, "[ERROR]: Local APIC", "The safety environment is not ready");
	return 0;
}
#ifndef LAPIC_SAFETY_STRING
#define LAPIC_SAFETY_STRING	"[Safety VM for Local APIC]: "
#endif
#define LAPIC_FIRST_VEC		16
#define LAPIC_MAX_VEC		255
#define LAPIC_TIMER_WAIT_MULTIPLIER 1000U
#define LAPIC_TIMER_INITIAL_VAL 1U
#define LAPIC_TEST_VEC		0x0E0U
#define LAPIC_TEST_INVALID_VEC	0U
#define LAPIC_TEST_INVALID_VEC1 15UL
#define LAPIC_TEST_VEC_HIGH	0x0E3U
#define LAPIC_INTR_TARGET_SELF	0U
#define LAPIC_INTR_TARGET_ID1	1U
#define LAPIC_INTR_TARGET_ID2	2U
#define LAPIC_MSR(reg)		(0x800U + ((unsigned)(reg) >> 4))
#define LAPIC_TPR_MAX		0x0FFU
#define LAPIC_TPR_MIN		0U
#define LAPIC_TPR_MID		0x20U
#define LAPIC_APIC_ID_VAL	0U
#define LAPIC_APIC_PPR_VAL	0U
#define LAPIC_APIC_LDR_VAL	0U
#define LAPIC_APIC_LVR_VAL	0U
#define LAPIC_APIC_RRR_VAL	0U
#define LAPIC_APIC_ISR0_VAL	0U
#define LAPIC_APIC_ISR1_VAL	0U
#define LAPIC_APIC_ISR2_VAL	0U
#define LAPIC_APIC_ISR3_VAL	0U
#define LAPIC_APIC_ISR4_VAL	0U
#define LAPIC_APIC_ISR5_VAL	0U
#define LAPIC_APIC_ISR6_VAL	0U
#define LAPIC_APIC_ISR7_VAL	0U
#define LAPIC_APIC_TMR0_VAL	0U
#define LAPIC_APIC_TMR1_VAL	0U
#define LAPIC_APIC_TMR2_VAL	0U
#define LAPIC_APIC_TMR3_VAL	0U
#define LAPIC_APIC_TMR4_VAL	0U
#define LAPIC_APIC_TMR5_VAL	0U
#define LAPIC_APIC_TMR6_VAL	0U
#define LAPIC_APIC_TMR7_VAL	0U
#define LAPIC_APIC_IRR0_VAL	0U
#define LAPIC_APIC_IRR1_VAL	0U
#define LAPIC_APIC_IRR2_VAL	0U
#define LAPIC_APIC_IRR3_VAL	0U
#define LAPIC_APIC_IRR4_VAL	0U
#define LAPIC_APIC_IRR5_VAL	0U
#define LAPIC_APIC_IRR6_VAL	0U
#define LAPIC_APIC_IRR7_VAL	0U
#define LAPIC_APIC_ESR_VAL	0U
#define LAPIC_APIC_TMCCT_VAL	0U
#define LAPIC_APIC_EOI_VAL	0
#define LAPIC_APIC_SELF_IPI_VAL 0
#define LAPIC_RESERVED_BIT(val)	val
#define LAPIC_NO_EXEC(fmt, cond, arg...) do { report(fmt, 0, ##arg); } while(0)

#define LAPIC_TEST_INVALID_MAX_VEC 15UL
#define LAPIC_ILLEGAL_VECTOR_LOOP_START(var,end) for( ; (var) <= (end); (vec) += 1) {
#define LAPIC_ILLEGAL_VECTOR_LOOP_END }

extern void send_sipi();
static inline void lapic_send_ipi(void)
{
	send_sipi();
}
#define LOCAL_APIC_AP_NR		1

#ifdef __x86_64__
/*test case which should run under 64bit  */

static unsigned long asm_lapic_xaddl(unsigned long *addr, unsigned size)
{
        unsigned int old = size;
        asm volatile ("LOCK xaddl %1, %0\n\t"
                :"+m"(*(volatile unsigned int *)addr), "+r"(old):: "memory");
        return (long)old;
}
void save_unchanged_reg(void)
{
        static unsigned long lapic_ap_percpu_addr = LAPIC_INIT_AP_BASE_ADDR;
        unsigned long ap_addr =
                asm_lapic_xaddl(&lapic_ap_percpu_addr, LAPIC_INIT_APIC_SIZE);
        unsigned int eax = rdmsr(MSR_IA32_APICBASE);
        *(volatile unsigned int *)(ap_addr +
                LAPIC_APIC_STRUCT(APIC_MSR_IA32_APICBASE1)) = eax;
}

static void lapic_busy_wait(void) {
        volatile unsigned long timeout = 1000000;
        while(--timeout)
                ;
}

static void lapic_write_eoi_non_zero(void *unused)
{
	apic_write(APIC_EOI, ~0U);
        mb();
}

static void lapic_write_delivery_mode_smi(void *addr)
{
        unsigned long reg = (unsigned long) addr;
        unsigned val = apic_read(reg);
        val &= ~APIC_MODE_MASK;
        val |= APIC_DM_SMI;
        apic_write(reg, val);
}

static atomic_t lapic_ipi_isr_count = {0};
static volatile unsigned long lapic_isr_cpuid = 0;
static volatile unsigned long lapic_isr_priority = 0UL;

static inline unsigned long lapic_get_lapic_isr_priority(void)
{
        return lapic_isr_priority;
}
static inline void lapic_record_lapic_isr_priority(void)
{
        lapic_isr_priority = apic_read(APIC_PROCPRI);
}

static inline unsigned long lapic_get_ipi_isr_record_cpuid(void)
{
	return lapic_isr_cpuid;
}
static inline void lapic_reset_ipi_isr_record_cpuid(void)
{
	lapic_isr_cpuid = 0UL;
}
static inline void lapic_record_lapic_isr_cpuid(unsigned pcpuid)
{
	unsigned long curr;
	curr = 0x1UL << pcpuid;
	asm volatile ("LOCK or %1, %0":"+m"(lapic_isr_cpuid): "r"(curr): "memory");
}
static void lapic_ipi_isr(isr_regs_t *regs)
{
        (void) regs;
        atomic_inc(&lapic_ipi_isr_count);
	lapic_record_lapic_isr_cpuid(apic_id());
	lapic_record_lapic_isr_priority();

        eoi();
}

static void lapic_ipi_isr_no_eoi(isr_regs_t *regs)
{
        (void) regs;
        atomic_inc(&lapic_ipi_isr_count);
}

/**
 * @brief case name APIC capability
 *
 * Summary: When a vCPU reads CPUID.1H, ACRN hypervisor shall set guest EDX [bit 9] to 1H.
 *  The Advanced Programmable Interrupt Controller (APIC), referred to in the
 *  following sections as the local APIC, is used by VM to receive and handle
 *  interrupts. Thus CPUID shall report the presence of Local APIC/xAPIC.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27696_apic_capability_001(void)
{
	struct cpuid id;
	id = cpuid(LAPIC_CPUID_APIC_CAPABILITY);
	report("%s", !!(id.d & LAPIC_CPUID_APIC_CAP_OK),
		"local_apic_rqmid_27696_apic_capability_001");

}

#if 0
/**
 * @brief case name Physical Local APIC/xAPIC Support
 *
 * Summary: Local APIC/xAPIC shall be available on the physical platform.
 *  APIC shall be available on the physical platform since it is used by VM to
 *  receive and handle interrupts.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27695_physical_lapic_support_001(void)
{
	struct cpuid id;
	id = cpuid(LAPIC_CPUID_APIC_CAPABILITY);
	report("%s", !!(id.d & LAPIC_CPUID_APIC_CAP_OK),
		"local_apic_rqmid_27695_physical_lapic_support_001");

	id = cpuid(LAPIC_CPUID_APIC_CAPABILITY);
	report("%s", !!(id.c & LAPIC_CPUID_APIC_CAP_X2APCI),
		"local_apic_rqmid_27695_physical_lapic_support_001");
}

/**
 * @brief case name x2APIC capability
 *
 * Summary: When a vCPU reads CPUID.1H, ACRN hypervisor shall set guest ECX[bit 21] to 1H.
 *  x2APIC mode is used to provide extended processor addressability to the VM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27694_x2apic_capability_001(void)
{
	struct cpuid id;
	id = cpuid(LAPIC_CPUID_APIC_CAPABILITY);
	report("%s", !!(id.c & LAPIC_CPUID_APIC_CAP_X2APCI),
		"local_apic_rqmid_27694_x2apic_capability_001");
}

/**
 * @brief case name Physical x2APIC Support
 *
 * Summary: x2APIC support shall be available on the physical platform.
 *  x2APIC shall be available on the physical platform. It is used to provide
 *  extended processor addressability.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27693_physical_x2apic_support_001(void)
{
	unsigned long apic_base_msr;
	apic_base_msr = rdmsr(MSR_IA32_APICBASE);

	if (!(apic_base_msr & APIC_EN)) {
		report("local_apic_rqmid_27693_physical_x2apic_support_001 - %s", 0,
			"Local APIC is not enabled");
		return;
	}

	apic_base_msr |= APIC_EXTD;
	wrmsr(MSR_IA32_APICBASE, apic_base_msr);
	mb();

	apic_base_msr = rdmsr(MSR_IA32_APICBASE);
	if ((apic_base_msr & (APIC_EN | APIC_EXTD)) !=
		(APIC_EN | APIC_EXTD)) {
		report("local_apic_rqmid_27693_physical_x2apic_support_001 - %s", 0,
			"Cannot enable x2APIC");
		return;
	}
	report("local_apic_rqmid_27693_physical_x2apic_support_001", 0);
}

/**
 * @brief case name Different x2APIC ID
 *
 * Summary: ACRN hypervisor shall guarantee that different guest LAPICs of the same VM have
 *  different extended LAPIC IDs.
 *  Each LAPIC shall have a unique ID to distinguish from other LAPICs
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27685_different_x2apic_id_001(void)
{
        int unique = 1;

	int apic_ids[LOCAL_APIC_AP_NR + 1];
	unsigned long addr = LAPIC_PRIVATE_MEM_ADDR;
	unsigned long offset = LAPIC_PRIVATE_SIZE;
	int i;
	int j;
	int nr = sizeof(apic_ids)/sizeof(*apic_ids);

	for(i=0; i<nr; ++i) {
		apic_ids[i] = (int) (*((volatile unsigned int *)(addr + offset * i +
			LAPIC_APIC_STRUCT(APIC_ID))));
	}

        for (i=0; (unique != 0) && (i < nr);  ++i) {
                for ( j=0; j<nr; ++j) {
                        if (i == j)
                                continue;
                        if (apic_ids[i] == apic_ids[j]) {
                                unique = 0;
                        }
                }
        }
	report("%s", unique == 1,
		"local_apic_rqmid_27685_different_x2apic_id_001");
}

/**
 * @brief case name Different Physical x2APIC ID
 *
 * Summary: Different LAPICs on the physical platform shall have different x2APIC IDs.
 *  Each LAPIC shall have a unique ID to distinguish from other LAPICs
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27684_different_physical_x2apic_id_001(void)
{
        int unique = 1;

	int apic_ids[LOCAL_APIC_AP_NR + 1];
	unsigned long addr = LAPIC_PRIVATE_MEM_ADDR;
	unsigned long offset = LAPIC_PRIVATE_SIZE;
	int i;
	int j;
	int nr = sizeof(apic_ids)/sizeof(*apic_ids);

	for(i=0; i<nr; ++i) {
		apic_ids[i] = (int) (*((volatile unsigned int *)(addr + offset * i +
				LAPIC_APIC_STRUCT(APIC_ID))));
	}

        for (i=0; (unique != 0) && (i < nr);  ++i) {
                for ( j=0; j<nr; ++j) {
                        if (i == j)
                                continue;
                        if (apic_ids[i] == apic_ids[j]) {
                                unique = 0;
                        }
                }
        }
	report("%s", unique == 1,
		"local_apic_rqmid_27684_different_x2apic_id_001");
}

/**
 * @brief case name APIC Base field state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest MSR_IA32_APICBASE of AP
 *  to 0FEE00C00H following INIT.
 *  In compliance with Chapter 10.4.4, Vol.3, SDM. INIT reset only occurs on APs,
 *  thus the BSP bit shall be cleared.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27681_apic_base_field_state_of_ap_following_init_001(void)
{
        unsigned int val;
	int i;
	unsigned long addr = LAPIC_PRIVATE_MEM_ADDR;
	unsigned long offset = LAPIC_PRIVATE_SIZE;

	for (i = 1; i <= LOCAL_APIC_AP_NR; i += 1) {
		val = *((volatile unsigned int *)(addr + offset * i +
				LAPIC_APIC_STRUCT(APIC_MSR_IA32_APICBASE)));

		report("%s for AP-%d", val == 0xfee00c00U,
		"local_apic_rqmid_27681_apic_base_field_state_of_ap_following_init_001", i);
	}
}


/**
 * @brief case name APIC Base field state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest MSR_IA32_APICBASE of BP to 0FEE00D00H
 *  following start-up.
 *  In compliance with Chapter 10.4.4, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27922_apic_base_field_state_of_bp_following_start_up_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_MSR_IA32_APICBASE)));
	report("%s", val == 0xfee00d00U,
		"local_apic_rqmid_27922_apic_base_field_state_following_start_up_001");
}

/**
 * @brief case name Software disable support
 *
 * Summary: ACRN hypervisor shall expose LAPIC software disable support to any VM, in
 *  compliance with Chapter 10.4.7.2, Vol. 3, SDM.
 *  LAPIC is in a software-disabled state following power-up or reset according to
 *  Chapter 10.4.7.1, Vol. 3, SDM. Thus software-disabled state shall be supported
 *  and available to VMs.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27677_software_disable_support_001(void)
{
	unsigned long apic_base_msr;
	unsigned int val;

	apic_base_msr = rdmsr(MSR_IA32_APICBASE);
	if (!(apic_base_msr & APIC_EN)) {
		report("%s - %s", 0,
			"local_apic_rqmid_27677_software_disable_support_001",
			"Local APIC is not enabled");
		return;
	}

	val = apic_read(APIC_LVTT);
	val &= ~APIC_LVT_MASKED;
	apic_write(APIC_LVTT, val);

	val = apic_read(APIC_SPIV);
	if (val & APIC_SPIV_APIC_ENABLED) {
		val &= ~APIC_SPIV_APIC_ENABLED;
	}
	apic_write(APIC_SPIV);
	mb();


	val = apic_read(APIC_LVTT);
	report("%s", val & APIC_LVT_MASKED != 0U,
		"local_apic_rqmid_27677_software_disable_support_001");
}

/**
 * @brief case name Encoding of LAPIC Version Register
 *
 * Summary: When a vCPU attempts to read LAPIC version register, ACRN hypervisor shall
 *  guarantee that the vCPU gets 1060015H.
 *  Keep LAPIC Version Register of VM the same with the target physical platform, in
 *  compliance with Chapter 10.4.8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27675_encoding_of_lapic_version_register_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVR)));
	report("%s", val == 0x1060015U,
		"local_apic_rqmid_27675_encoding_of_lapic_version_register_001");
}

static atomic_t lapic_timer_isr_count;
static void lapic_timer_isr(isr_regs_t *regs)
{
        (void) regs;
        atomic_inc(&lapic_timer_isr_count);

        eoi();
}

/**
 * @brief case name Expose LVT support
 *
 * Summary: ACRN hypervisor shall expose local vector table to any VM, in compliance with
 *  Chapter 10.5.1, Vol.3 and table 10-6, Vol. 3, SDM.
 *  The local vector table (LVT) allows software to specify the manner in which the
 *  local interrupts are delivered to the processor core. ACRN hypervisor shall
 *  provide LVT CMCI Register, LVT Timer Register, LVT Thermal Monitor Register, LVT
 *  Performance Counter Register, LVT LINT0 Register, LVT LINT1 Register, LVT Error
 *  Register for VM to use in compliance with Chapter 10.5 Vol.3 and table 10-6, Vol.
 *  3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27674_expose_lvt_support_001(void)
{
	const char *lvt_reg = "APIC Timer";
	const unsigned int vec = LAPIC_TEST_VEC;

	unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
	unsigned int lvtt;

	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	apic_write(APIC_TMICT, 0);

	handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

	irq_enable();

	lvtt &= ~APIC_LVT_TIMER_MASK;
	lvtt |= APIC_LVT_TIMER_ONESHOT;

        apic_write(APIC_LVTT, lvtt);
        mb();

	apic_write(APIC_TMICT, initial_value);

	while(atomic_read(&lapic_timer_isr_count) < 1) {
		-- initial_value;
		if (initial_value == 0U) {
			apic_write(APIC_TMICT, 0);
			break;
		}
	}
	report("%s - %s", atomic_read(&lapic_timer_isr_count) == 1,
		"local_apic_rqmid_27674_expose_lvt_support_001",
		lvt_reg);
}

/**
 * @brief case name LVT CMCI state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LVT CMCI to 00010000H following INIT.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27673_lvt_cmci_state_following_init_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVTCMCI)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27673_lvt_cmci_state_following_init_001");
}

/**
 * @brief case name LVT CMCI state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LVT CMCI to 00010000H following
 *  start-up.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27672_lvt_cmci_state_following_start_up_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVTCMCI)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27672_lvt_cmci_state_following_start_up_001");
}

/**
 * @brief case name LVT LINT0 state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LVT LINT0 to 00010000H following INIT.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27671_lvt_lint0_state_following_init_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVT0)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27671_lvt_lint0_state_following_init_001");
}

/**
 * @brief case name LVT LINT0 state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LVT LINT0 to 00010000H following
 *  start-up.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27670_lvt_lint0_state_following_start_up_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVT0)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27670_lvt_lint0_state_following_start_up_001");
}

/**
 * @brief case name LVT LINT1 state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LVT LINT1 to 00010000H following INIT.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27669_lvt_lint1_state_following_init_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVT1)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27669_lvt_lint1_state_following_init_001");
}

/**
 * @brief case name LVT LINT1 state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LVT LINT1 to 00010000H following
 *  start-up.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27668_lvt_lint1_state_following_start_up_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVT1)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27668_lvt_lint1_state_following_start_up_001");
}

/**
 * @brief case name LVT Error Register state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LVT Error Register to 00010000H
 *  following INIT.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27667_lvt_error_register_state_following_init_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVTERR)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27667_lvt_error_register_state_following_init_001");
}

/**
 * @brief case name LVT Error Register state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LVT Error Register to 00010000H
 *  following start-up.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27666_lvt_error_register_state_following_start_up_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVTERR)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27666_lvt_error_register_state_following_start_up_001");
}

/**
 * @brief case name LVT Thermal Monitor Register state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LVT Thermal Monitor Register to
 *  00010000H following INIT.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27665_lvt_thermal_monitor_register_state_following_init_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVTTHMR)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27665_lvt_thermal_monitor_register_state_following_init_001");
}

/**
 * @brief case name LVT Thermal Monitor Register state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LVT Thermal Monitor Register to
 *  00010000H following start-up,.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27664_lvt_thermal_monitor_register_state_following_start_up_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVTTHMR)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27664_lvt_thermal_monitor_register_state_following_start_up_001");
}

/**
 * @brief case name LVT Thermal Monitor Register state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LVT Thermal Monitor Register to
 *  00010000H following start-up,.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_0_lvt_thermal_monitor_register_state_following_start_up_002(void)
{
}

/**
 * @brief case name LVT Performance Counter Register state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LVT Performance Counter Register to
 *  00010000H following INIT.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27663_lvt_performance_counter_register_state_following_init_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVTPC)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27663_lvt_performance_counter_register_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140232 LVT Performance Counter Register state following start-up */
/*    <1: 140232 - 27662> Local APIC_LVT Performance Counter Register state following start-up_001 */

/**
 * @brief case name LVT Performance Counter Register state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LVT Performance Counter Register to
 *  00010000H following start-up.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27662_lvt_performance_counter_register_state_following_start_up_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVTPC)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27662_lvt_performance_counter_register_state_following_start_up_001");
}

/**
 * @brief case name LVT Timer Register state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LVT Timer Register to 00010000H
 *  following INIT.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27661_lvt_timer_register_state_following_init_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVTT)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27661_lvt_timer_register_state_following_init_001");
}

/**
 * @brief case name LVT Timer Register state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LVT Timer Register to 00010000H
 *  following start-up.
 *  In compliance with Figure 10-8, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27660_lvt_timer_register_state_following_start_up_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_LVTT)));
	report("%s", val == 0x10000U,
		"local_apic_rqmid_27660_lvt_timer_register_state_following_start_up_001");
}


/* Summary: 1 Case for Requirement: 140235 Expose LAPIC error handling */
/*    <1: 140235 - 27659> Local APIC_Expose LAPIC error handling_001 */

/**
 * @brief case name Expose LAPIC error handling
 *
 * Summary: ACRN hypervisor shall expose error handling support to any VM in compliance with
 *  Chapter 10.5.3 and table 10-6, Vol 3, SDM.
 *  ESR will be used to record errors detected during interrupt handling, in
 *  compliance with Chapter 10.5.3 and table 10-6, Vol 3, SDM.
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27659_expose_lapic_error_handling_001(void)
{

        const unsigned int vec = LAPIC_TEST_INVALID_VEC;

        unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
        unsigned int lvtt;
        unsigned int updated_lvtt;

        irq_disable();
        atomic_set(&lapic_timer_isr_count, 0);

        wrmsr(MSR_IA32_TSCDEADLINE, 0);
        apic_write(APIC_TMICT, 0);

        handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

        irq_enable();

        lvtt &= ~APIC_LVT_TIMER_MASK;
        lvtt |= APIC_LVT_TIMER_ONESHOT;
        apic_write(APIC_LVTT, lvtt);
        mb();

        updated_lvtt = apic_read(APIC_LVTT);
        report("%s - %s", (updated_lvtt & 0x0FFU) == vec,
                "local_apic_rqmid_27659_expose_lapic_error_handling_001",
                "The APIC LVT Timer vector should set the correct vector");

        apic_write(APIC_TMICT, initial_value);
        mb();
        nop();

        initial_value *= LAPIC_TIMER_WAIT_MULTIPLIER;
        while(atomic_read(&lapic_timer_isr_count) < 1) {
                -- initial_value;
                if (initial_value == 0U) {
                        apic_write(APIC_TMICT, 0);
                        break;
                }
        }

        report("%s - %s", atomic_read(&lapic_timer_isr_count) == 0,
                "local_apic_rqmid_27659_expose_lapic_error_handling_001",
                "Should not trigger Timer Interrupt for Invlaid vector");
        report("%s - %s", apic_read(APIC_ESR) != 0,
                "local_apic_rqmid_27659_expose_lapic_error_handling_001",
                "APIC_ESR shoud set the Received Illegal Vector[bit 6]");
}

/**
 * @brief case name Expose LAPIC error handling
 *
 * Summary: ACRN hypervisor shall expose error handling support to any VM in compliance with
 *  Chapter 10.5.3 and table 10-6, Vol 3, SDM.
 *  ESR will be used to record errors detected during interrupt handling, in
 *  compliance with Chapter 10.5.3 and table 10-6, Vol 3, SDM.
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_0_expose_lapic_error_handling_002(void)
{
        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_INVALID_VEC;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned int val;

        unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
        if (!(apic_base_msr & APIC_EXTD))
                return;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        apic_write(APIC_TASKPRI, LAPIC_TPR_MID);

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);
        mb();

        nop();
        lapic_busy_wait();

        report("%s - %s", apic_read(APIC_ESR) != 0,
                "local_apic_rqmid_0_expose_lapic_error_handling_002",
		"APIC_ESR should not be 0");
        report("%s - %s", atomic_read(&lapic_ipi_isr_count) == 0,
                "local_apic_rqmid_0_expose_lapic_error_handling_002",
		"#IPI exeception should not be triggered");
}


/* Summary: 1 Case for Requirement: 140237 ESR state following INIT */
/*    <1: 140237 - 27658> Local APIC_ESR state following INIT_001 */

/**
 * @brief case name ESR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest ESR to 0H following INIT.
 *  In compliance with Figure 10-9, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27658_esr_state_following_init_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ESR)));
	report("%s", val == 0U, "local_apic_rqmid_27658_esr_state_following_init_001");
}

/**
 * @brief case name ESR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest ESR to 0H following start-up.
 *  In compliance with Figure 10-9, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27657_esr_state_following_start_up_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ESR)));
	report("%s", val == 0U, "local_apic_rqmid_27657_esr_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 140240 Physical LAPIC SVR support */
/*    <1: 140240 - 27731> Local APIC_Physical LAPIC SVR support_001 */

/**
 * @brief case name Physical LAPIC SVR support
 *
 * Summary: Spurious-Interrupt Vector Register (SVR) shall be available on the physical
 *  platform in compliance with Chapter 10.9, Vol.3, SDM.
 *  SVR will be used for Spurious interrupt and enable/disable APIC, Focus Processor
 *  Checking, EOI-Broadcast Suppression, in compliance with Chapter 10.9, Vol.3,
 *  SDM. Physical platform shall have it.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27731_physical_lapic_svr_support_001(void)
{
	unsigned int val;
	unsigned int old;
	unsigned int x;
	old = apic_read(APIC_SPIV);

	val = old ^ APIC_EN;
	val |= APIC_VECTOR_MASK;

	apic_write(APIC_SPIV, val);
	mb();

	x = apic_read(APIC_SPIV);
	apic_write(APIC_SPIV, old);

	report("%s", x == val,
		"local_apic_rqmid_27731_physical_lapic_svr_support_001");
}

/**
 * @brief case name SVR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LAPIC SVR to 0FFH following INIT.
 *  In compliance with Figure 10-23, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27656_svr_state_following_init_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_SPIV)));
	report("%s", val == 0xFFU, "local_apic_rqmid_27656_svr_state_following_init_001");
}

/**
 * @brief case name SVR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LAPIC SVR to 0FFH following start-up.
 *  In compliance with Figure 10-23, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27655_svr_state_following_start_up_001(void)
{
	unsigned int val = *((volatile unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_SPIV)));
	report("%s", val == 0xFFU,
		"local_apic_rqmid_27655_svr_state_following_start_up_001");
}

/**
 * @brief case name Expose ARAT support
 *
 * Summary: ACRN hypervisor shall expose APIC Timer always running feature to any VM, in
 *  compliance with Chapter 10.5.4, Vol.3, SDM. For precision, we need the
 *  processor’s APIC timer runs at a constant rate regardless of P-state
 *  transitions and it continues to run at the same rate in deep C-states.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27654_expose_arat_support_001(void)
{
	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
        struct cpuid id;

	if (!(apic_base_msr & APIC_EXTD))
		return;

        id = cpuid(LAPIC_TIMER_CAPABILITY);
        report("%s", (id.a & LAPIC_TIMER_CAPABILITY_ARAT) != 0U,
		"local_apic_rqmid_27654_expose_arat_support_001");
}

/**
 * @brief case name Expose ARAT support
 *
 * Summary: ACRN hypervisor shall expose APIC Timer always running feature to any VM, in
 *  compliance with Chapter 10.5.4, Vol.3, SDM. For precision, we need the
 *  processor’s APIC timer runs at a constant rate regardless of P-state
 *  transitions and it continues to run at the same rate in deep C-states.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27653_expose_arat_support_002(void)
{
	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
        struct cpuid id;

	if (apic_base_msr & APIC_EXTD)
		return;

        id = cpuid(LAPIC_TIMER_CAPABILITY);
        report("%s", (id.a & LAPIC_TIMER_CAPABILITY_ARAT) != 0U,
		"local_apic_rqmid_27653_expose_arat_support_002");
}

/**
 * @brief case name Physical ARAT support
 *
 * Summary: APIC Timer always running feature shall be supported on the physical platform.
 *  For precision, we need the processor’s APIC timer runs at a constant rate
 *  regardless of P-state transitions and it continues to run at the same rate in
 *  deep C-states.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27652_physical_arat_support_001(void)
{
        struct cpuid id;
        id = cpuid(LAPIC_TIMER_CAPABILITY);
        report("%s", (id.a & LAPIC_TIMER_CAPABILITY_ARAT) != 0U,
		"local_apic_rqmid_27652_physical_arat_support_001");
}

/* Summary: 2 Case for Requirement: 140245 Expose TSC deadline timer mode support */
/*    <1: 140245 - 27651> Local APIC_Expose TSC deadline timer mode support_001 */

/**
 * @brief case name Expose TSC deadline timer mode support
 *
 * Summary: ACRN hypervisor shall expose TSC deadline timer mode support to any VM, in
 *  compliance with Chapter 10.5.4.1, Vol.3, SDM. TSC-deadline timer mode can be used
 *  by software to use the local APIC timer to signal an interrupt at an absolute
 *  time.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27651_expose_tsc_deadline_timer_mode_support_001(void)
{
	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);

	const unsigned int vec = LAPIC_TEST_VEC;

	unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
	unsigned int lvtt;

	if (!(apic_base_msr & APIC_EXTD))
		return;

	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	apic_write(APIC_TMICT, 0);

	handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

	irq_enable();

	lvtt &= ~APIC_LVT_TIMER_MASK;
	lvtt |= APIC_LVT_TIMER_TSCDEADLINE;

	wrmsr(MSR_IA32_TSCDEADLINE, rdmsr(MSR_IA32_TSC));
        mb();

	while(atomic_read(&lapic_timer_isr_count) < 1) {
		-- initial_value;
		if (initial_value == 0U) {
			wrmsr(MSR_IA32_TSCDEADLINE, 0);
			break;
		}
	}
	report("%s", atomic_read(&lapic_timer_isr_count) == 1,
		"local_apic_rqmid_27651_expose_tsc_deadline_timer_mode_support_001");
}

/*    <2: 140245 - 27650> Local APIC_Expose TSC deadline timer mode support_002 */

/**
 * @brief case name Expose TSC deadline timer mode support
 *
 * Summary: ACRN hypervisor shall expose TSC deadline timer mode support to any VM, in
 *  compliance with Chapter 10.5.4.1, Vol.3, SDM. TSC-deadline timer mode can be used
 *  by software to use the local APIC timer to signal an interrupt at an absolute
 *  time.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27650_expose_tsc_deadline_timer_mode_support_002(void)
{
	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);

	const unsigned int vec = LAPIC_TEST_VEC;

	unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
	unsigned int lvtt;

	if (apic_base_msr & APIC_EXTD)
		return;

	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	apic_write(APIC_TMICT, 0);

	handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

	irq_enable();

	lvtt &= ~APIC_LVT_TIMER_MASK;
	lvtt |= APIC_LVT_TIMER_TSCDEADLINE;

	wrmsr(MSR_IA32_TSCDEADLINE, rdmsr(MSR_IA32_TSC));
	mb();

	while(atomic_read(&lapic_timer_isr_count) < 1) {
		-- initial_value;
		if (initial_value == 0U) {
			wrmsr(MSR_IA32_TSCDEADLINE, 0);
			break;
		}
	}
	report("%s", atomic_read(&lapic_timer_isr_count) == 1,
		"local_apic_rqmid_27650_expose_tsc_deadline_timer_mode_support_002");
}

/* Summary: 1 Case for Requirement: 140246 Physical TSC deadline timer mode support */
/*    <1: 140246 - 27649> Local APIC_Physical TSC deadline timer mode support_001 */

/**
 * @brief case name Physical TSC deadline timer mode support
 *
 * Summary: TSC deadline timer mode support shall be available on the physical platform.
 *  TSC-deadline timer mode allows software to use the local APIC timer to signal an
 *  interrupt at an absolute time. Physical platform shall have this supported since
 *  it will be exopse to VM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27649_physical_tsc_deadline_timer_mode_support_001(void)
{
	const unsigned int vec = LAPIC_TEST_VEC;

	unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
	unsigned int lvtt;

	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	apic_write(APIC_TMICT, 0);

	handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

	irq_enable();

	lvtt &= ~APIC_LVT_TIMER_MASK;
	lvtt |= APIC_LVT_TIMER_TSCDEADLINE;

	wrmsr(MSR_IA32_TSCDEADLINE, rdmsr(MSR_IA32_TSC));
	mb();

	while(atomic_read(&lapic_timer_isr_count) < 1) {
		-- initial_value;
		if (initial_value == 0U) {
			wrmsr(MSR_IA32_TSCDEADLINE, 0);
			break;
		}
	}
	report("%s", atomic_read(&lapic_timer_isr_count) == 1,
		"local_apic_rqmid_27649_physical_tsc_deadline_timer_mode_support_001");
}

/* Summary: 2 Case for Requirement: 140247 Expose One-shot timer mode support */
/*    <1: 140247 - 27648> Local APIC_Expose One-shot timer mode support_001 */

/**
 * @brief case name Expose One-shot timer mode support
 *
 * Summary: ACRN hypervisor shall expose one-shot timer mode support to any VM, in
 *  compliance with Chapter 10.5.4, Vol.3, SDM. The timer shall can be configured
 *  through the timer LVT entry for one-shot mode. In one-shot mode, the timer is
 *  started by programming its initial-count register. The initial count value is
 *  then copied into the currentcount register and count-down begins. After the timer
 *  reaches zero, an timer interrupt is generated and the timer remains at its 0
 *  value until reprogrammed.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27648_expose_one_shot_timer_mode_support_001(void)
{
	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);

	const unsigned int vec = LAPIC_TEST_VEC;

	unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
	unsigned int lvtt;

	if (!(apic_base_msr & APIC_EXTD))
		return;


	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	apic_write(APIC_TMICT, 0);

	handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

	irq_enable();

	lvtt &= ~APIC_LVT_TIMER_MASK;
	lvtt |= APIC_LVT_TIMER_ONESHOT;

        apic_write(APIC_LVTT, lvtt);
        mb();

	apic_write(APIC_TMICT, initial_value);
	mb();
	nop();

	while(atomic_read(&lapic_timer_isr_count) < 1) {
		-- initial_value;
		if (initial_value == 0U) {
			apic_write(APIC_TMICT, 0);
			break;
		}
	}
	report("%s", atomic_read(&lapic_timer_isr_count) == 1,
		"local_apic_rqmid_27648_expose_one_shot_timer_mode_support_001");
}

/*    <2: 140247 - 27647> Local APIC_Expose One-shot timer mode support_002 */

/**
 * @brief case name Expose One-shot timer mode support
 *
 * Summary: ACRN hypervisor shall expose one-shot timer mode support to any VM, in
 *  compliance with Chapter 10.5.4, Vol.3, SDM. The timer shall can be configured
 *  through the timer LVT entry for one-shot mode. In one-shot mode, the timer is
 *  started by programming its initial-count register. The initial count value is
 *  then copied into the currentcount register and count-down begins. After the timer
 *  reaches zero, an timer interrupt is generated and the timer remains at its 0
 *  value until reprogrammed.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27647_expose_one_shot_timer_mode_support_002(void)
{
	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);

	const unsigned int vec = LAPIC_TEST_VEC;

	unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
	unsigned int lvtt;

	if (apic_base_msr & APIC_EXTD)
		return;


	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	apic_write(APIC_TMICT, 0);

	handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

	irq_enable();

	lvtt &= ~APIC_LVT_TIMER_MASK;
	lvtt |= APIC_LVT_TIMER_ONESHOT;
        apic_write(APIC_LVTT, lvtt);
        mb();

	apic_write(APIC_TMICT, initial_value);
        mb();
	nop();

	while(atomic_read(&lapic_timer_isr_count) < 1) {
		-- initial_value;
		if (initial_value == 0U) {
			apic_write(APIC_TMICT, 0);
			break;
		}
	}
	report("%s", atomic_read(&lapic_timer_isr_count) == 1,
		"local_apic_rqmid_27647_expose_one_shot_timer_mode_support_002");
}

/* Summary: 1 Case for Requirement: 140248 Physical One-shot timer mode support */
/*    <1: 140248 - 27646> Local APIC_Physical One-shot timer mode support_001 */

/**
 * @brief case name Physical One-shot timer mode support
 *
 * Summary: One-shot timer mode support shall be available on the physical platform.
 *  The timer shall can be configured through the timer LVT entry for one-shot mode.
 *  In one-shot mode, the timer is started by programming its initial-count
 *  register. The initial count value is then copied into the currentcount register
 *  and count-down begins. After the timer reaches zero, an timer interrupt is
 *  generated and the timer remains at its 0 value until reprogrammed.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27646_physical_one_shot_timer_mode_support_001(void)
{
	const unsigned int vec = LAPIC_TEST_VEC;

	unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
	unsigned int lvtt;

	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	apic_write(APIC_TMICT, 0);

	handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

	irq_enable();

	lvtt &= ~APIC_LVT_TIMER_MASK;
	lvtt |= APIC_LVT_TIMER_PERIODIC;

        apic_write(APIC_LVTT, lvtt);
        mb();

	apic_write(APIC_TMICT, initial_value);
        mb();
	nop();

	while(atomic_read(&lapic_timer_isr_count) < 2) {
		-- initial_value;
		if (initial_value == 0U) {
			apic_write(APIC_TMICT, 0);
			break;
		}
	}
	report("%s", atomic_read(&lapic_timer_isr_count) == 1,
		"local_apic_rqmid_27646_physical_one_shot_timer_mode_support_001");
}

/* Summary: 2 Case for Requirement: 140249 Expose Periodic timer mode support */
/*    <1: 140249 - 27645> Local APIC_Expose Periodic timer mode support_001 */

/**
 * @brief case name Expose Periodic timer mode support
 *
 * Summary: ACRN hypervisor shall expose periodic timer mode support to any VM, in
 *  compliance with Chapter 10.5.4, Vol.3, SDM. The timer shall can be configured
 *  through the timer LVT entry for periodic mode. In periodic mode, the
 *  current-count register is automatically reloaded from the initial-count register
 *  when the count reaches 0 and a timer interrupt is generated, and the count-down
 *  is repeated. If during the count-down process the initial-count register is set,
 *  counting will restart, using the new initial-count value. The initial-count
 *  register is a read-write register; the current-count register is read only.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27645_expose_periodic_timer_mode_support_001(void)
{
	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);

	const unsigned int vec = LAPIC_TEST_VEC;

	unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
	unsigned int lvtt;

	if (apic_base_msr & APIC_EXTD)
		return;


	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	apic_write(APIC_TMICT, 0);

	handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

	irq_enable();

	lvtt &= ~APIC_LVT_TIMER_MASK;
	lvtt |= APIC_LVT_TIMER_PERIODIC;

        apic_write(APIC_LVTT, lvtt);
        mb();

	initial_value *= LAPIC_TIMER_WAIT_MULTIPLIER;
	apic_write(APIC_TMICT, initial_value);
        mb();
	nop();

	initial_value *= LAPIC_TIMER_WAIT_MULTIPLIER;
	while(atomic_read(&lapic_timer_isr_count) < 2) {
		-- initial_value;
		if (initial_value == 0U) {
			apic_write(APIC_TMICT, 0);
			break;
		}
	}
	report("%s", atomic_read(&lapic_timer_isr_count) >= 2,
		"local_apic_rqmid_27645_expose_periodic_timer_mode_support_001");
}

/*    <2: 140249 - 27644> Local APIC_Expose Periodic timer mode support_002 */

/**
 * @brief case name Expose Periodic timer mode support
 *
 * Summary: ACRN hypervisor shall expose periodic timer mode support to any VM, in
 *  compliance with Chapter 10.5.4, Vol.3, SDM. The timer shall can be configured
 *  through the timer LVT entry for periodic mode. In periodic mode, the
 *  current-count register is automatically reloaded from the initial-count register
 *  when the count reaches 0 and a timer interrupt is generated, and the count-down
 *  is repeated. If during the count-down process the initial-count register is set,
 *  counting will restart, using the new initial-count value. The initial-count
 *  register is a read-write register; the current-count register is read only.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27644_expose_periodic_timer_mode_support_002(void)
{
	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);

	const unsigned int vec = LAPIC_TEST_VEC;

	unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
	unsigned int lvtt;

	if (apic_base_msr & APIC_EXTD)
		return;


	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	apic_write(APIC_TMICT, 0);

	handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

	irq_enable();

	lvtt &= ~APIC_LVT_TIMER_MASK;
	lvtt |= APIC_LVT_TIMER_ONESHOT;

        apic_write(APIC_LVTT, lvtt);
        mb();

	initial_value *= LAPIC_TIMER_WAIT_MULTIPLIER;
	apic_write(APIC_TMICT, initial_value);
        mb();
	nop();

	initial_value *= LAPIC_TIMER_WAIT_MULTIPLIER;
	while(atomic_read(&lapic_timer_isr_count) < 2) {
		-- initial_value;
		if (initial_value == 0U) {
			apic_write(APIC_TMICT, 0);
			break;
		}
	}
	report("%s", atomic_read(&lapic_timer_isr_count) >= 2,
		"local_apic_rqmid_27644_expose_periodic_timer_mode_support_002");
}

/* Summary: 1 Case for Requirement: 140250 Physical Periodic timer mode support */
/*    <1: 140250 - 27643> Local APIC_Physical Periodic timer mode support_001 */

/**
 * @brief case name Physical Periodic timer mode support
 *
 * Summary: Periodic timer support shall be available on the physical platform.
 *  The timer shall can be configured through the timer LVT entry for periodic mode.
 *  In periodic mode, the current-count register is automatically reloaded from the
 *  initial-count register when the count reaches 0 and a timer interrupt is
 *  generated, and the count-down is repeated. If during the count-down process the
 *  initial-count register is set, counting will restart, using the new initial-count
 *  value. The initial-count register is a read-write register; the current-count
 *  register is read only.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27643_physical_periodic_timer_mode_support_001(void)
{
	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);

	const unsigned int vec = LAPIC_TEST_VEC;

	unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
	unsigned int lvtt;

	if (apic_base_msr & APIC_EXTD)
		return;


	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	wrmsr(MSR_IA32_TSCDEADLINE, 0);
	apic_write(APIC_TMICT, 0);

	handle_irq(vec, lapic_timer_isr);
        lvtt = apic_read(APIC_LVTT);
        lvtt &= ~APIC_LVT_MASKED;
        lvtt &= ~APIC_VECTOR_MASK;
        lvtt |= vec;

        apic_write(APIC_LVTT, lvtt);
        mb();

	irq_enable();

	lvtt &= ~APIC_LVT_TIMER_MASK;
	lvtt |= APIC_LVT_TIMER_ONESHOT;
        apic_write(APIC_LVTT, lvtt);
        mb();

	initial_value *= LAPIC_TIMER_WAIT_MULTIPLIER;
	apic_write(APIC_TMICT, initial_value);
	mb();
	nop();

	while(atomic_read(&lapic_timer_isr_count) < 2) {
		-- initial_value;
		if (initial_value == 0U) {
			apic_write(APIC_TMICT, 0);
			break;
		}
	}
	report("%s - %s", atomic_read(&lapic_timer_isr_count) >= 2,
		"local_apic_rqmid_27643_physical_periodic_timer_mode_support_001");
}

/* Summary: 1 Case for Requirement: 140251 LAPIC Timer Mode Configration */
/*    <1: 140251 - 27697> Local APIC_LAPIC Timer Mode Configration_001 */

/**
 * @brief case name LAPIC Timer Mode Configration
 *
 * Summary: ACRN hypervisor shall expose timer mode configration support to any VM, in
 *  compliance with Chapter 10.5.4, Vol.3, SDM. The timer can be configured through
 *  the timer LVT entry for one-shot mode, periodic mode or TSC-Deadline Mode, in
 *  compliance with Chapter 10.5.4, Vol.3, SDM.
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27697_lapic_timer_mode_configration_001(void)
{
	static unsigned int mode[3] = {
		APIC_LVT_TIMER_ONESHOT,
		APIC_LVT_TIMER_PERIODIC,
		APIC_LVT_TIMER_TSCDEADLINE,
	};
	static const char *mode_str[3] = {
		"One-Shot",
		"Periodic",
		"TSC deadline",
	};
	int i;

	for(i=0; i<3; ++i) {
		const unsigned int vec = LAPIC_TEST_VEC;
		int isr_expect = 1;
		int result;

		unsigned initial_value = LAPIC_TIMER_INITIAL_VAL;
		unsigned int lvtt;

		irq_disable();
		atomic_set(&lapic_timer_isr_count, 0);

		wrmsr(MSR_IA32_TSCDEADLINE, 0);
		apic_write(APIC_TMICT, 0);

		handle_irq(vec, lapic_timer_isr);
		lvtt = apic_read(APIC_LVTT);
		lvtt &= ~APIC_LVT_MASKED;
		lvtt &= ~APIC_VECTOR_MASK;
		lvtt |= vec;

		apic_write(APIC_LVTT, lvtt);
		mb();

		irq_enable();

		lvtt &= ~APIC_LVT_TIMER_MASK;
		lvtt |= mode[i];
		apic_write(APIC_LVTT, lvtt);
		mb();

		if (mode[i] == APIC_LVT_TIMER_PERIODIC)
			initial_value *= LAPIC_TIMER_WAIT_MULTIPLIER;

		if (mode[i] == APIC_LVT_TIMER_TSCDEADLINE)
			wrmsr(MSR_IA32_TSCDEADLINE, rdmsr(MSR_IA32_TSC));
		else
			apic_write(APIC_TMICT, initial_value);
		mb();
		nop();

		if (mode[i] == APIC_LVT_TIMER_PERIODIC)
			isr_expect = 2;

		initial_value *= LAPIC_TIMER_WAIT_MULTIPLIER;
		while(atomic_read(&lapic_timer_isr_count) < isr_expect) {
			-- initial_value;
			if (initial_value == 0U) {
				apic_write(APIC_TMICT, 0);
				break;
			}
		}

		if (mode[i] == APIC_LVT_TIMER_PERIODIC)
			result = atomic_read(&lapic_timer_isr_count) >= 2;
		else
			result = atomic_read(&lapic_timer_isr_count) == 1;
		report("%s - %s",  result,
			"local_apic_rqmid_27697_lapic_timer_mode_configration_001",
			mode_str[i]);
	}
}

/* Summary: 4 Case for Requirement: 140787 Expose IPI support */
/*    <1: 140787 - 27642> Local APIC_Expose IPI support_001 */

static int test_for_interrupt(unsigned vector, const char *msg)
{
        const char *sub_msg = "test_for_interrupt";
        const unsigned int vec = vector & 0x0FFU;
        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned val;
        int ret = 0;

        atomic_set(&lapic_ipi_isr_count, 0);
        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        if (atomic_read(&lapic_ipi_isr_count) == 1)
                return ret = 1;
        printf("%s: %s - %s %u", ret == 1 ? "pass": "failure", msg, sub_msg, vec);
        return ret;
}

/**
 * @brief case name Expose IPI support
 *
 * Summary: ACRN hypervisor shall expose IPI support to any VM, in compliance with Chapter
 *  10.6, Chapter 10.12.10 and Figure 10-28, Vol.3, SDM.
 *  IPI mechanism will be used by VM to issuing inter-processor interrupts. This
 *  include ICR and LDR. As only x2apic mode is supported, DFR is not available to
 *  VMs.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27642_expose_ipi_support_001(void)
{
	const unsigned int destination = LAPIC_INTR_TARGET_SELF;
	const unsigned int vec = LAPIC_TEST_VEC;
	const unsigned int mode =
		APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_FIXED;
	unsigned int val;

	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
	if (!(apic_base_msr & APIC_EXTD))
		return;

	val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	atomic_set(&lapic_ipi_isr_count, 0);

	irq_disable();
	handle_irq(vec, lapic_ipi_isr);
        irq_enable();

	if (apic_read(APIC_ESR) != 0U)
		apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();

	report("%s", atomic_read(&lapic_ipi_isr_count) == 1,
		"local_apic_rqmid_27642_expose_ipi_support_001");
}


/*    <2: 140787 - 27641> Local APIC_Expose IPI support_002 */

/**
 * @brief case name Expose IPI support
 *
 * Summary: ACRN hypervisor shall expose IPI support to any VM, in compliance with Chapter
 *  10.6, Chapter 10.12.10 and Figure 10-28, Vol.3, SDM.
 *  IPI mechanism will be used by VM to issuing inter-processor interrupts. This
 *  include ICR and LDR. As only x2apic mode is supported, DFR is not available to
 *  VMs.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27641_expose_ipi_support_002(void)
{
	const unsigned int destination = LAPIC_INTR_TARGET_ID1;
	const unsigned int vec = LAPIC_TEST_VEC;
	const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
	unsigned int val;

	val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	atomic_set(&lapic_ipi_isr_count, 0);

	irq_disable();
	handle_irq(vec, lapic_ipi_isr);
        irq_enable();

	if (apic_read(APIC_ESR) != 0U)
		apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();

	report("%s", atomic_read(&lapic_ipi_isr_count) == 1,
		"local_apic_rqmid_27641_expose_ipi_support_002");
}

/*    <3: 140787 - 27640> Local APIC_Expose IPI support_003 */

/**
 * @brief case name Expose IPI support
 *
 * Summary: ACRN hypervisor shall expose IPI support to any VM, in compliance with Chapter
 *  10.6, Chapter 10.12.10 and Figure 10-28, Vol.3, SDM.
 *  IPI mechanism will be used by VM to issuing inter-processor interrupts. This
 *  include ICR and LDR. As only x2apic mode is supported, DFR is not available to
 *  VMs.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27640_expose_ipi_support_003(void)
{
	const unsigned int destination = LAPIC_INTR_TARGET_ID1;
	const unsigned int vec = LAPIC_TEST_VEC;
	const unsigned int mode = APIC_DEST_LOGICAL | APIC_DM_FIXED;
	unsigned int val;

	val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	atomic_set(&lapic_ipi_isr_count, 0);

	irq_disable();
	handle_irq(vec, lapic_ipi_isr);
        irq_enable();

	if (apic_read(APIC_ESR) != 0U)
		apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();

	report("%s", atomic_read(&lapic_ipi_isr_count) == 1,
		"local_apic_rqmid_27640_expose_ipi_support_003");
}

/*    <4: 140787 - 27639> Local APIC_Expose IPI support_004 */

/**
 * @brief case name Expose IPI support
 *
 * Summary: ACRN hypervisor shall expose IPI support to any VM, in compliance with Chapter
 *  10.6, Chapter 10.12.10 and Figure 10-28, Vol.3, SDM.
 *  IPI mechanism will be used by VM to issuing inter-processor interrupts. This
 *  include ICR and LDR. As only x2apic mode is supported, DFR is not available to
 *  VMs.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27639_expose_ipi_support_004(void)
{
	const unsigned int destination = LAPIC_INTR_TARGET_ID1;
	const unsigned int vec = LAPIC_TEST_VEC;
	const unsigned int mode = APIC_DEST_LOGICAL | APIC_DM_FIXED;
	unsigned int val;

	val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	atomic_set(&lapic_ipi_isr_count, 0);

	irq_disable();
	handle_irq(vec, lapic_ipi_isr);
        irq_enable();

	if (apic_read(APIC_ESR) != 0U)
		apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();

	report("%s", atomic_read(&lapic_ipi_isr_count) == 1,
		"local_apic_rqmid_27639_expose_ipi_support_004");
}

/* Summary: 1 Case for Requirement: 140788 Physical IPI support */
/*    <1: 140788 - 27638> Local APIC_Physical IPI support_001 */

/**
 * @brief case name Physical IPI support
 *
 * Summary: IPI support shall be available on the physical platform, in compliance with
 *  Chapter 10.6, Vol.3, SDM. IPI mechanism will be used by VM to issuing
 *  interprocessor interrupts. The physical platform shall have this supported.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27638_physical_ipi_support_001(void)
{
	const unsigned int destination = LAPIC_INTR_TARGET_SELF;
	const unsigned int vec = LAPIC_TEST_VEC;
	const unsigned int mode =
		APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_FIXED;
	unsigned int val;

	val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	atomic_set(&lapic_ipi_isr_count, 0);

	irq_disable();
	handle_irq(vec, lapic_ipi_isr);
        irq_enable();

	if (apic_read(APIC_ESR) != 0U)
		apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();

	report("%s", atomic_read(&lapic_ipi_isr_count) == 1,
		"local_apic_rqmid_27638_physical_ipi_support_001");
}

/* Summary: 1 Case for Requirement: 140789 ICR state following INIT */
/*    <1: 140789 - 27637> Local APIC_ICR state following INIT_001 */

/**
 * @brief case name ICR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest ICR to 0H following INIT.
 *  In compliance with Figure 10-12, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27637_icr_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
			LAPIC_APIC_STRUCT(APIC_ICR)));
	report("%s", val == 0U,
		"local_apic_rqmid_27637_icr_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140790 ICR state following start-up */
/*    <1: 140790 - 27636> Local APIC_ICR state following start-up_001 */

/**
 * @brief case name ICR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest ICR to 0H following start-up.
 *  In compliance with Figure 10-12, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27636_icr_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ICR)));
	report("%s", val == 0U,
		"local_apic_rqmid_27636_icr_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 140791 LDR state following INIT */
/*    <1: 140791 - 27635> Local APIC_LDR state following INIT_001 */

/**
 * @brief case name LDR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LDR to 0H following INIT, in compliance
 *  with Figure 10-13, Vol.3, SDM.
 *  In compliance with Figure 10-13, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27635_ldr_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
			LAPIC_APIC_STRUCT(APIC_LDR)));
	report("%s", val == 0U,
		"local_apic_rqmid_27635_ldr_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140792 LDR state following start-up */
/*    <1: 140792 - 27634> Local APIC_LDR state following start-up_001 */

/**
 * @brief case name LDR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LDR to 0H following start-up, in
 *  compliance with Figure 10-13, Vol.3, SDM.
 *  In compliance with Figure 10-13, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27634_ldr_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
			LAPIC_APIC_STRUCT(APIC_LDR)));
	report("%s", val == 0U,
		"local_apic_rqmid_27634_ldr_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 140793 DFR state following INIT */
/*    <1: 140793 - 27633> Local APIC_DFR state following INIT_001 */

/**
 * @brief case name DFR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest DFR to FFFFFFFFH following INIT, in
 *  compliance with Figure 10-14, Vol.3, SDM.
 *  In compliance with Figure 10-14, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27633_dfr_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
			LAPIC_APIC_STRUCT(APIC_DFR)));
	report("%s", val == 0xFFFFFFFFU,
		"local_apic_rqmid_27633_dfr_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140794 DFR state following start-up */
/*    <1: 140794 - 27632> Local APIC_DFR state following start-up_001 */

/**
 * @brief case name DFR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest DFR to FFFFFFFFH following start-up, in
 *  compliance with Figure 10-14, Vol.3, SDM.
 *  In compliance with Figure 10-14, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27632_dfr_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
			LAPIC_APIC_STRUCT(APIC_DFR)));
	report("%s", val == 0x0FFFFFFFFU,
		"local_apic_rqmid_27632_dfr_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 140795 APR state following INIT */
/*    <1: 140795 - 27631> Local APIC_APR state following INIT_001 */

/**
 * @brief case name APR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest APR to 0H following INIT, in compliance
 *  with Figure 10-15, Vol.3, SDM.
 *  In compliance with Figure 10-15, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27631_apr_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ARBPRI)));
	report("%s", val == 0U,
		"local_apic_rqmid_27631_apr_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140796 APR state following start-up */
/*    <1: 140796 - 27630> Local APIC_APR state following start-up_001 */

/**
 * @brief case name APR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest APR to 0H following start-up, in
 *  compliance with Figure 10-15, Vol.3, SDM.
 *  In compliance with Figure 10-15, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27630_apr_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ARBPRI)));
	report("%s", val == 0U,
		"local_apic_rqmid_27630_apr_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 140797 xAPIC IPI Delivery in Physical Destination Mode  */
/*    <1: 140797 - 27628> Local APIC_xAPIC IPI Delivery in Physical Destination Mode_001 */

/**
 * @brief case name xAPIC IPI Delivery in Physical Destination Mode
 *
 * Summary: ACRN hypervisor shall support a LAPIC in xAPIC mode can send an IPI by
 *  specifying destination with a local APIC ID Destination Field of ICR, in
 *  compliance with Chapter 10.6.2.1, Vol.3, SDM.
 *  xAPIC IPI behavior in compliance with Chapter 10.6.2.1, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27628_xapic_ipi_delivery_in_physical_destination_mode_001(void)
{
	/* Another core by IPI */
	const unsigned int destination = LAPIC_INTR_TARGET_ID2;
	const unsigned int vec = LAPIC_TEST_VEC;
	const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
	unsigned int val;

	val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	atomic_set(&lapic_ipi_isr_count, 0);

	irq_disable();
	handle_irq(vec, lapic_ipi_isr);
        irq_enable();

	if (apic_read(APIC_ESR) != 0U)
		apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();

	report("%s", atomic_read(&lapic_ipi_isr_count) == 1,
		"local_apic_rqmid_27628_xapic_ipi_delivery_in_physical_destination_mode_001");
}

/* Summary: 1 Case for Requirement: 140798 xAPIC IPI Delivery in Logical Destination Mode */
/*    <1: 140798 - 27627> Local APIC_xAPIC IPI Delivery in Logical Destination Mode_001 */

/**
 * @brief case name xAPIC IPI Delivery in Logical Destination Mode
 *
 * Summary: ACRN hypervisor shall support a LAPIC in xAPIC mode can send an IPI by
 *  specifying destination with an 8-bit message destination address (MDA) in
 *  Destination Field of ICR, in compliance with Chapter 10.6.2.2, Vol.3, SDM.
 *  xAPIC IPI behavior in compliance with Chapter 10.6.2.2, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27627_xapic_ipi_delivery_in_logical_destination_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27627_xapic_ipi_delivery_in_logical_destination_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140799 xAPIC IPI Delivery in Broadcast/Self Delivery Mode */
/*    <1: 140799 - 27626> Local APIC_xAPIC IPI Delivery in Broadcast/Self Delivery Mode_001 */

/**
 * @brief case name xAPIC IPI Delivery in Broadcast/Self Delivery Mode
 *
 * Summary: ACRN hypervisor shall support a LAPIC in xAPIC mode can send an IPI with a
 *  Broadcast/Self destination by configuring Shorthand of ICR, in compliance with
 *  Chapter 10.6.2.3, Vol.3, SDM.
 *  xAPIC IPI behavior in compliance with Chapter 10.6.2.3, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27626_xapic_ipi_delivery_in_broadcast_self_delivery_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27626_xapic_ipi_delivery_in_broadcast_self_delivery_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140800 xAPIC IPI Delivery in Lowest Priority Delivery Mode */
/*    <1: 140800 - 27625> Local APIC_xAPIC IPI Delivery in Lowest Priority Delivery Mode_001 */

/**
 * @brief case name xAPIC IPI Delivery in Lowest Priority Delivery Mode
 *
 * Summary: ACRN hypervisor shall support a LAPIC in xAPIC mode can send an IPI to several
 *  processors by using the logical or shorthand destination mechanism for selecting
 *  the processor, in compliance with Chapter 10.6.2.4, Vol.3, SDM.
 *  xAPIC IPI behavior in compliance with Chapter 10.6.2.4, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27625_xapic_ipi_delivery_in_lowest_priority_delivery_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27625_xapic_ipi_delivery_in_lowest_priority_delivery_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140801 xAPIC IPI Reception in Physical Destination Mode  */
/*    <1: 140801 - 27624> Local APIC_xAPIC IPI Reception in Physical Destination Mode_001 */

/**
 * @brief case name xAPIC IPI Reception in Physical Destination Mode
 *
 * Summary: ACRN hypervisor shall support a LAPIC in xAPIC mode can receive an IPI with a
 *  local APIC ID destination, in compliance with Chapter 10.6.2.1, Vol.3, SDM.
 *  xAPIC IPI behavior in compliance with Chapter 10.6.2.1, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27624_xapic_ipi_reception_in_physical_destination_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27624_xapic_ipi_reception_in_physical_destination_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140802 xAPIC IPI Reception in Logical Destination Mode */
/*    <1: 140802 - 27623> Local APIC_xAPIC IPI Reception in Logical Destination Mode_001 */

/**
 * @brief case name xAPIC IPI Reception in Logical Destination Mode
 *
 * Summary: ACRN hypervisor shall support a LAPIC in xAPIC mode can receive an IPI with a
 *  MDA by comparing the MDA with its LDR and DFR, in compliance with Chapter
 *  10.6.2.2, Vol.3, SDM.
 *  xAPIC IPI behavior in compliance with Chapter 10.6.2.2, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27623_xapic_ipi_reception_in_logical_destination_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27623_xapic_ipi_reception_in_logical_destination_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140803 xAPIC IPI Reception in Broadcast/Self Delivery Mode */
/*    <1: 140803 - 27622> Local APIC_xAPIC IPI Reception in Broadcast/Self Delivery Mode_001 */

/**
 * @brief case name xAPIC IPI Reception in Broadcast/Self Delivery Mode
 *
 * Summary: ACRN hypervisor shall support a LAPIC in xAPIC mode can receive an IPI with a
 *  Broadcast/Self destination configured in Shorthand of ICR, in compliance with
 *  Chapter 10.6.2.3, Vol.3, SDM.
 *  xAPIC IPI behavior in compliance with Chapter 10.6.2.3, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27622_xapic_ipi_reception_in_broadcast_self_delivery_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27622_xapic_ipi_reception_in_broadcast_self_delivery_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140804 xAPIC IPI Reception in Lowest Priority Delivery Mode */
/*    <1: 140804 - 27621> Local APIC_xAPIC IPI Reception in Lowest Priority Delivery Mode_001 */

/**
 * @brief case name xAPIC IPI Reception in Lowest Priority Delivery Mode
 *
 * Summary: ACRN hypervisor shall support a LAPIC in xAPIC mode can receive an IPI if it has
 *  the lowest processor priority among a group of destination processors, in
 *  compliance with Chapter 10.6.2.4, Vol.3, SDM.
 *  xAPIC IPI behavior in compliance with Chapter 10.6.2.4, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27621_xapic_ipi_reception_in_lowest_priority_delivery_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27621_xapic_ipi_reception_in_lowest_priority_delivery_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140805 x2APIC IPI Delivery in Physical Destination Mode  */
/*    <1: 140805 - 27620> Local APIC_x2APIC IPI Delivery in Physical Destination Mode_001 */

/**
 * @brief case name x2APIC IPI Delivery in Physical Destination Mode
 *
 * Summary: ACRN hypervisor shall expose IPI delivery in physical destination mode, in
 *  compliance with Chapter 10.12.9, Vol.3, SDM.
 *  x2APIC IPI behavior in compliance with Chapter 10.12.9, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27620_x2apic_ipi_delivery_in_physical_destination_mode_001(void)
{
	const unsigned int destination = LAPIC_INTR_TARGET_SELF;
	const unsigned int vec = LAPIC_TEST_VEC;
	const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
	unsigned int val;

	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
	if (!(apic_base_msr & APIC_EXTD))
		return;

	val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	atomic_set(&lapic_ipi_isr_count, 0);

	irq_disable();
	handle_irq(vec, lapic_ipi_isr);
        irq_enable();

	if (apic_read(APIC_ESR) != 0U)
		apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
	lapic_busy_wait();

	report("%s", atomic_read(&lapic_ipi_isr_count) == 1,
		"local_apic_rqmid_27620_x2apic_ipi_delivery_in_physical_destination_mode_001");
}

/* Summary: 1 Case for Requirement: 140806 x2APIC IPI Delivery in Logical Destination Mode */
/*    <1: 140806 - 27619> Local APIC_x2APIC IPI Delivery in Logical Destination Mode_001 */

/**
 * @brief case name x2APIC IPI Delivery in Logical Destination Mode
 *
 * Summary: When a vCPU writes LAPIC ICR and the new guest LAPIC ICR [bit 11] is 1H, ACRN
 *  hypervisor shall guarantee that the IPI issue request is ignored.
 *  Logical destination can be used neither in Zephyr nor Linux in the current
 *  scope.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27619_x2apic_ipi_delivery_in_logical_destination_mode_001(void)
{
        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = APIC_DEST_LOGICAL | APIC_DM_FIXED;
        unsigned int val;

        unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
        if (!(apic_base_msr & APIC_EXTD))
                return;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


        atomic_set(&lapic_ipi_isr_count, 0);
	lapic_reset_ipi_isr_record_cpuid();

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 1) &&
		     (lapic_get_ipi_isr_record_cpuid() == (unsigned long)destination),
                "local_apic_rqmid_27619_x2apic_ipi_delivery_in_logical_destination_mode_001");
}


/* Summary: 1 Case for Requirement: 140807 x2APIC IPI Delivery in "Self/All Including Self/All Excluding Self" Delivery Mode */
/*    <1: 140807 - 27618> Local APIC_x2APIC IPI Delivery in "Self/All Including Self/All Excluding Self" Delivery Mode_001 */

/**
 * @brief case name x2APIC IPI Delivery in "Self/All Including Self/All Excluding Self" Delivery Mode
 *
 * Summary: When a vCPU writes LAPIC ICR and the new guest LAPIC ICR [bit 19:18] is
 *  different from 0H, ACRN hypervisor shall guarantee that the IPI issue request is
 *  ignored.
 *  Delivery shorthand is not a hard requirement in the current scope which is a
 *  logical partition scenario with a Zephyr and Linux. The same functionality can be
 *  implemented without shorthand by explicitly send IPI to each core that shall be
 *  involved.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27618_x2apic_ipi_delivery_in_self_all_including_self_all_excluding_self_delivery_mode_001(void)
{
	const unsigned int destination = LAPIC_INTR_TARGET_SELF;
	const unsigned int vec = LAPIC_TEST_VEC;
	const unsigned int mode =
		APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_FIXED;
	unsigned int val;

	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
	if (!(apic_base_msr & APIC_EXTD))
		return;

	val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	atomic_set(&lapic_ipi_isr_count, 0);

	irq_disable();
	handle_irq(vec, lapic_ipi_isr);
        irq_enable();

	if (apic_read(APIC_ESR) != 0U)
		apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);
        mb();

        nop();
	lapic_busy_wait();

	report("%s", atomic_read(&lapic_ipi_isr_count) == 0,
		"local_apic_rqmid_27618_x2apic_ipi_delivery_in_"
		"self_all_including_self_all_excluding_self_delivery_mode_001");
}

void local_apic_rqmid_0_x2apic_ipi_delivery_in_self_all_including_self_all_excluding_self_delivery_mode_002(void)
{
	const unsigned int destination = LAPIC_INTR_TARGET_SELF;
	const unsigned int vec = LAPIC_TEST_VEC;
	const unsigned int mode =
		APIC_DEST_ALLBUT | APIC_DEST_PHYSICAL | APIC_DM_FIXED;
	unsigned int val;

	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
	if (!(apic_base_msr & APIC_EXTD))
		return;

	val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	atomic_set(&lapic_ipi_isr_count, 0);

	irq_disable();
	handle_irq(vec, lapic_ipi_isr);
        irq_enable();

	if (apic_read(APIC_ESR) != 0U)
		apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
	lapic_busy_wait();

	report("%s", atomic_read(&lapic_ipi_isr_count) == 0,
		"local_apic_rqmid_0_x2apic_ipi_delivery_in_"
		"self_all_including_self_all_excluding_self_delivery_mode_002");
}

void local_apic_rqmid_0_x2apic_ipi_delivery_in_self_all_including_self_all_excluding_self_delivery_mode_003(void)
{
	const unsigned int destination = LAPIC_INTR_TARGET_SELF;
	const unsigned int vec = LAPIC_TEST_VEC;
	const unsigned int mode =
		APIC_DEST_ALLINC | APIC_DEST_PHYSICAL | APIC_DM_FIXED;
	unsigned int val;

	unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
	if (!(apic_base_msr & APIC_EXTD))
		return;

	val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	atomic_set(&lapic_ipi_isr_count, 0);

	irq_disable();
	handle_irq(vec, lapic_ipi_isr);
        irq_enable();

	if (apic_read(APIC_ESR) != 0U)
		apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
	lapic_busy_wait();

	report("%s", atomic_read(&lapic_ipi_isr_count) == 0,
		"local_apic_rqmid_0_x2apic_ipi_delivery_in_"
		"self_all_including_self_all_excluding_self_delivery_mode_003");
}

/* Summary: 1 Case for Requirement: 140808 x2APIC IPI Delivery in Lowest Priority Delivery Mode */
/*    <1: 140808 - 27617> Local APIC_x2APIC IPI Delivery in Lowest Priority Delivery Mode_001 */

/**
 * @brief case name x2APIC IPI Delivery in Lowest Priority Delivery Mode
 *
 * Summary: ACRN hypervisor shall hide x2APIC IPI Delivery in Lowest Priority Delivery Mode,
 *  in compliance with Chapter 10.12.9, Vol.3, SDM.
 *  It will not been support to keep simplicity.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27617_x2apic_ipi_delivery_in_lowest_priority_delivery_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27617_x2apic_ipi_delivery_in_lowest_priority_delivery_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140809 x2APIC IPI Reception in Physical Destination Mode */
/*    <1: 140809 - 27616> Local APIC_x2APIC IPI Reception in Physical Destination Mode_001 */

/**
 * @brief case name x2APIC IPI Reception in Physical Destination Mode
 *
 * Summary: ACRN hypervisor shall support x2APIC IPI Reception in Physical Destination Mode
 *  , in compliance with Chapter 10.12.9, Vol.3, SDM.
 *  x2APIC IPI behavior in compliance with Chapter 10.12.9, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27616_x2apic_ipi_reception_in_physical_destination_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27616_x2apic_ipi_reception_in_physical_destination_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140810 x2APIC IPI Reception in Logical Destination Mode */
/*    <1: 140810 - 27615> Local APIC_x2APIC IPI Reception in Logical Destination Mode_001 */

/**
 * @brief case name x2APIC IPI Reception in Logical Destination Mode
 *
 * Summary: ACRN hypervisor shall hide x2APIC IPI Reception in Logical Destination Mode, in
 *  compliance with Chapter 10.12.10, Vol.3, SDM.
 *  It will not been support to keep simplicity.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27615_x2apic_ipi_reception_in_logical_destination_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27615_x2apic_ipi_reception_in_logical_destination_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140811 x2APIC IPI Reception in "Self/All Including Self/All Excluding Self" Delivery Mode */
/*    <1: 140811 - 27614> Local APIC_x2APIC IPI Reception in "Self/All Including Self/All Excluding Self" Delivery Mode_001 */

/**
 * @brief case name x2APIC IPI Reception in "Self/All Including Self/All Excluding Self" Delivery Mode
 *
 * Summary: ACRN hypervisor shall hide x2APIC IPI Reception when the destination shorhand is
 *  different from 0H, in compliance with Chapter 10.6.2.3, Vol.3, SDM.
 *  It will not been support to keep simplicity.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27614_x2apic_ipi_reception_in_self_all_including_self_all_excluding_self_delivery_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27614_x2apic_ipi_reception_in_"
		"self_all_including_self_all_excluding_self_delivery_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140812 x2APIC IPI Reception in Lowest Priority Delivery Mode */
/*    <1: 140812 - 27613> Local APIC_x2APIC IPI Reception in Lowest Priority Delivery Mode_001 */

/**
 * @brief case name x2APIC IPI Reception in Lowest Priority Delivery Mode
 *
 * Summary: ACRN hypervisor shall hide x2APIC IPI Reception in Lowest Priority Delivery
 *  Mode, in compliance with Chapter 10.12.9, Vol.3, SDM.
 *  It will not been support to keep simplicity.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27613_x2apic_ipi_reception_in_lowest_priority_delivery_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27613_x2apic_ipi_reception_in_lowest_priority_delivery_mode_001"
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140813 TPR state following INIT */
/*    <1: 140813 - 27612> Local APIC_TPR state following INIT_001 */

/**
 * @brief case name TPR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest TPR to 0H following INIT.
 *  In compliance with Figure 10-18, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27612_tpr_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TASKPRI)));
	report("%s", val == 0U,
		"local_apic_rqmid_27612_tpr_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140814 TPR state following start-up */
/*    <1: 140814 - 27611> Local APIC_TPR state following start-up_001 */

/**
 * @brief case name TPR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest TPR to 0H following start-up.
 *  In compliance with Figure 10-18, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27611_tpr_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TASKPRI)));
	report("%s", val == 0U,
		"local_apic_rqmid_27611_tpr_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 140815 PPR state following INIT */
/*    <1: 140815 - 27610> Local APIC_PPR state following INIT_001 */

/**
 * @brief case name PPR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest PPR to 0H following INIT.
 *  In compliance with Figure 10-19, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27610_ppr_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_PROCPRI)));
	report("%s", val == 0U,
		"local_apic_rqmid_27610_ppr_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140816 PPR state following start-up */
/*    <1: 140816 - 27609> Local APIC_PPR state following start-up_001 */

/**
 * @brief case name PPR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest PPR to 0H following start-up.
 *  In compliance with Figure 10-19, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27609_ppr_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_PROCPRI)));
	report("%s", val == 0U,
		"local_apic_rqmid_27609_ppr_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 140817 IRR state following INIT */
/*    <1: 140817 - 27608> Local APIC_IRR state following INIT_001 */

/**
 * @brief case name IRR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27608_irr_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(0))));
	report("%s", val == 0U,
		"local_apic_rqmid_27608_irr_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140818 IRR state following start-up */
/*    <1: 140818 - 27607> Local APIC_IRR state following start-up_001 */

/**
 * @brief case name IRR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27607_irr_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(0))));
	report("%s", val == 0U,
		"local_apic_rqmid_27607_irr_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 140819 ISR state following INIT */
/*    <1: 140819 - 27606> Local APIC_ISR state following INIT_001 */

/**
 * @brief case name ISR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27606_isr_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(0))));
	report("%s", val == 0U,
		"local_apic_rqmid_27606_isr_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140820 ISR state following start-up */
/*    <1: 140820 - 27605> Local APIC_ISR state following start-up_001 */

/**
 * @brief case name ISR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27605_isr_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(0))));
	report("%s", val == 0U,
		"local_apic_rqmid_27605_isr_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 140821 TMR state following INIT */
/*    <1: 140821 - 27604> Local APIC_TMR state following INIT_001 */

/**
 * @brief case name TMR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27604_tmr_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(0))));
	report("%s", val == 0U,
		"local_apic_rqmid_27604_tmr_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140822 TMR state following start-up */
/*    <1: 140822 - 27603> Local APIC_TMR state following start-up_001 */

/**
 * @brief case name TMR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27603_tmr_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(0))));
	report("%s", val == 0U,
		"local_apic_rqmid_27603_tmr_state_following_start_up_001");
}

/**
 * @brief case name IRR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30672_irr_state_following_init_002(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(1))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30675_irr_state_following_init_003(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(2))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30677_irr_state_following_init_004(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(3))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30678_irr_state_following_init_005(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(4))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30680_irr_state_following_init_006(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(5))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30681_irr_state_following_init_007(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(6))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30682_irr_state_following_init_008(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(7))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30683_irr_state_following_start_up_002(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(1))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30684_irr_state_following_start_up_003(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(2))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30687_irr_state_following_start_up_004(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(3))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30688_irr_state_following_start_up_005(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(4))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30690_irr_state_following_start_up_006(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(5))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30691_irr_state_following_start_up_007(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(6))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name IRR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest IRR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30693_irr_state_following_start_up_008(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_IRR + LAPIC_IRR_INDEX(7))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30712_isr_state_following_init_002(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(1))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30713_isr_state_following_init_003(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(2))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30714_isr_state_following_init_004(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(3))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30715_isr_state_following_init_005(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(4))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30716_isr_state_following_init_006(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(5))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30717_isr_state_following_init_007(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(6))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30718_isr_state_following_init_008(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(7))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30719_isr_state_following_start_up_002(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(1))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30720_isr_state_following_start_up_003(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(2))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30721_isr_state_following_start_up_004(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(3))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30722_isr_state_following_start_up_005(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(4))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30724_isr_state_following_start_up_006(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(5))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30726_isr_state_following_start_up_007(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(6))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name ISR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest ISR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30727_isr_state_following_start_up_008(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_ISR + LAPIC_ISR_INDEX(7))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30694_tmr_state_following_init_002(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(1))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30695_tmr_state_following_init_003(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(2))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30696_tmr_state_following_init_004(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(3))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30697_tmr_state_following_init_005(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(4))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30698_tmr_state_following_init_006(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(5))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30699_tmr_state_following_init_007(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(6))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following INIT.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30700_tmr_state_following_init_008(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(7))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30702_tmr_state_following_start_up_002(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(1))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30703_tmr_state_following_start_up_003(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(3))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30706_tmr_state_following_start_up_004(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(3))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30708_tmr_state_following_start_up_005(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(4))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30709_tmr_state_following_start_up_006(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(5))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30710_tmr_state_following_start_up_007(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(6))));
        report("%s", val == 0U, msg);
}

/**
 * @brief case name TMR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest TMR to 0H following start-up.
 *  In compliance with Figure 10-20, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30711_tmr_state_following_start_up_008(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMR + LAPIC_TMR_INDEX(7))));
        report("%s", val == 0U, msg);
}

// 199393: TODO
// 199394: TODO

// 199396
/**
 * @brief case name Timer initial count register state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LAPIC timer initial count register
 *  to 0H following start-up.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30730_timer_initial_count_register_state_following_start_up_001(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMICT)));
        report("%s", val == 0U, msg);
}

// 199397
/**
 * @brief case name Timer initial count register state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LAPIC timer initial count register
 *  to 0H following INIT.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30731_timer_initial_count_register_state_following_init_001(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMICT)));
        report("%s", val == 0U, msg);
}

// 199398
/**
 * @brief case name Timer current count register state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LAPIC timer current count register
 *  to 0H following start-up.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30733_timer_current_count_register_state_following_start_up_001(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMCCT)));
        report("%s", val == 0U, msg);
}

// 199399
/**
 * @brief case name Timer current count register state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LAPIC timer current count register
 *  to 0H following INIT.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30735_timer_current_count_register_state_following_init_001(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TMCCT)));
        report("%s", val == 0U, msg);
}

// 199400
/**
 * @brief case name DCR state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest LAPIC DCR to 0H following start-up.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30738_dcr_state_following_start_up_001(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TDCR)));
        report("%s", val == 0U, msg);
}

// 199401
/**
 * @brief case name DCR state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest LAPIC DCR to 0H following INIT.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30739_dcr_state_following_init_001(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_TDCR)));
        report("%s", val == 0U, msg);
}

// 199402
/**
 * @brief case name IA32_TSC_DEADLINE state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest IA32_TSC_DEADLINE to 0H following start-up.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30740_ia32_tsc_deadline_state_following_start_up_001(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_MSR_IA32_TSCDEADLINE)));
        report("%s", val == 0U, msg);
}

// 199403
/**
 * @brief case name IA32_TSC_DEADLINE state following INIT
 *
 * Summary: ACRN hypervisor shall keep guest IA32_TSC_DEADLINE unchanged following INIT.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30742_ia32_tsc_deadline_state_following_init_001(void)
{
	const char *msg = __func__;
        unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_MSR_IA32_TSCDEADLINE)));
        report("%s", val == 0U, msg);
}

// 199955
/**
 * @brief case name APIC Base field state following INIT
 *
 * Summary: ACRN hypervisor shall keep guest IA32_APIC_BASE unchanged following INIT.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
static void local_apic_rqmid_30744_apic_base_field_state_following_init_001(void)
{
        static const char *msg = __func__;
        static const unsigned long addr = LAPIC_PRIVATE_MEM_ADDR;
        static const unsigned long offset = LAPIC_PRIVATE_SIZE;

        static unsigned int apic_msr[LOCAL_APIC_AP_NR + 1];
        static const int nr = sizeof(apic_msr)/sizeof(*apic_msr);
        static int ret = 1;
        static int i;

        for (i = 0; i < nr; i += 1) {
                apic_msr[i] = *((unsigned int *)(addr + offset * i +
                                LAPIC_APIC_STRUCT(APIC_MSR_IA32_APICBASE)));
        }

        /* START-UP IPI to AP */
        lapic_send_ipi();

        for (i = 1; i < nr; i += 1) {
                if( (apic_msr[i] != *((unsigned int *)(addr + offset * i +
                                LAPIC_APIC_STRUCT(APIC_MSR_IA32_APICBASE1))))) {
                        ret = 0;
                }
        }

        report("%s", ret == 1, msg);
}

/******************************************************************************/

/* Summary: 1 Case for Requirement: 140823 EOI state following INIT */
/*    <1: 140823 - 27602> Local APIC_EOI state following INIT_001 */

/**
 * @brief case name EOI state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest EOI to 0H following INIT, in compliance
 *  with Figure 10-21, Vol.3, SDM.
 *  In compliance with Figure 10-21, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27602_eoi_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_EOI)));
	report("%s", val == 0U,
		"local_apic_rqmid_27602_eoi_state_following_init_001");
}

/* Summary: 1 Case for Requirement: 140824 EOI state following start-up */
/*    <1: 140824 - 27601> Local APIC_EOI state following start-up_001 */

/**
 * @brief case name EOI state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest EOI to 0H following start-up, in
 *  compliance with Figure 10-21, Vol.3, SDM.
 *  In compliance with Figure 10-21, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27601_eoi_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_EOI)));
	report("%s", val == 0U,
		"local_apic_rqmid_27601_eoi_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 140825 Expose Interrupt Priority Feature */
/*    <1: 140825 - 27932> Local APIC_Expose Interrupt Priority Feature_001 */

/**
 * @brief case name Expose Interrupt Priority Feature
 *
 * Summary: ACRN hypervisor shall expose task priority support to any VM, in compliance with
 *  Chapter 10.8.3.1, Vol.3, SDM.
 *  VM will use this feature to process Interrupt Priority.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27932_expose_interrupt_priority_feature_001(void)
{
        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned int val;

        unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
        if (!(apic_base_msr & APIC_EXTD))
                return;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        apic_write(APIC_TASKPRI, LAPIC_TPR_MAX);

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        report("%s - %s", atomic_read(&lapic_ipi_isr_count) == 0,
                "local_apic_rqmid_27932_expose_interrupt_priority_feature_001",
                "blocked");

        nop();
        lapic_busy_wait();

        apic_write(APIC_TASKPRI, LAPIC_TPR_MIN);
        report("%s", atomic_read(&lapic_ipi_isr_count) == 1,
                "local_apic_rqmid_27932_expose_interrupt_priority_feature_001");
}


/* Summary: 1 Case for Requirement: 140827 Read-Only PPR */
/*    <1: 140827 - 27600> Local APIC_Read-Only PPR_001 */

static void lapic_read_only_ppr_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	wrmsr(LAPIC_MSR(APIC_PROCPRI), LAPIC_APIC_PPR_VAL);
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

/**
 * @brief case name Read-Only PPR
 *
 * Summary: ACRN hypervisor shall guarantee the PPR is read-only.
 *  In compliance with Chapter 10.8.3.1, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27600_read_only_ppr_001(void)
{
	const char *msg = "local_apic_rqmid_27600_read_only_ppr_001";
	int err = 0;

	err = test_for_exception(GP_VECTOR, lapic_read_only_ppr_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 140828 The value of PPR */
/*    <1: 140828 - 27930> Local APIC_The value of PPR_001 */

/**
 * @brief case name The value of PPR
 *
 * Summary: ACRN hypervisor shall guarantee the value of PPR is calculated in compliance
 *  with Chapter 10.8.3.1, Vol.3, SDM.
 *  In compliance with Chapter 10.8.3.1, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27930_the_value_of_ppr_001(void)
{
        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC_HIGH;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned int val;

        unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
        if (!(apic_base_msr & APIC_EXTD))
                return;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        apic_write(APIC_TASKPRI, LAPIC_TPR_MID);

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 1) &&
                        ((lapic_get_lapic_isr_priority() == (vec & 0xF0U)) ||
                                (lapic_get_lapic_isr_priority() == vec)),
                "local_apic_rqmid_27930_the_value_of_ppr_001");
}


/* Summary: 1 Case for Requirement: 140831 Expose Interrupt Acceptance for Fixed Interrupts Infrastructure */
/*    <1: 140831 - 27927> Local APIC_Expose Interrupt Acceptance for Fixed Interrupts Infrastructure_001 */

// static atomic_t lapic_ipi_isr_count = {0};
struct isr_extra_info_s {
        unsigned int vec;
        atomic_t cnt;
        volatile unsigned irr0;
        volatile unsigned isr0;
        volatile unsigned tmr0;
        volatile unsigned irr1;
        volatile unsigned isr1;
        volatile unsigned tmr1;
        volatile unsigned irr2;
        volatile unsigned isr2;
        volatile unsigned tmr2;
};
static struct isr_extra_info_s lapic_isr_extra_info;
static void lapic_ipi_isr_extra(isr_regs_t *regs)
{
        struct isr_extra_info_s *info = &lapic_isr_extra_info;
        (void) regs;

        atomic_inc(&info->cnt);
        info->irr1 = apic_read(APIC_IRR + (((unsigned)info->vec >> 5) << 4));
        info->isr1 = apic_read(APIC_ISR + (((unsigned)info->vec >> 5) << 4));
        info->tmr1 = apic_read(APIC_TMR + (((unsigned)info->vec >> 5) << 4));

        eoi();

        info->irr1 = apic_read(APIC_IRR + (((unsigned)info->vec >> 5) << 4));
        info->isr1 = apic_read(APIC_ISR + (((unsigned)info->vec >> 5) << 4));
        info->tmr1 = apic_read(APIC_TMR + (((unsigned)info->vec >> 5) << 4));
}

/**
 * @brief case name Expose Interrupt Acceptance for Fixed Interrupts Infrastructure
 *
 * Summary: ACRN hypervisor shall expose interrupt handling support to any VM, in compliance
 *  with Chapter 10.8.3 and Chapter 10.8.4, Vol.3, SDM.
 *  IRR, ISR, TMR will be used for Fixed Interrupt Acceptance.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27927_expose_interrupt_acceptance_for_fixed_interrupts_infrastructure_001(void)
{
	const char *msg = "local_apic_rqmid_27927_expose_interrupt_acceptance_"
			"for_fixed_interrupts_infrastructure_001";
        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = LAPIC_TEST_VEC;
        // const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        const unsigned int mode = APIC_DEST_LOGICAL | APIC_DM_FIXED;
        struct isr_extra_info_s *info = &lapic_isr_extra_info;
        unsigned int val;

        unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
        if (!(apic_base_msr & APIC_EXTD))
                return;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr_extra);
        info->vec = vec;
        atomic_set(&info->cnt, 0);

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        info->irr0 = apic_read(APIC_IRR + (((unsigned)info->vec >> 5) << 4));
        info->isr0 = apic_read(APIC_ISR + (((unsigned)info->vec >> 5) << 4));
        info->tmr0 = apic_read(APIC_TMR + (((unsigned)info->vec >> 5) << 4));

        irq_enable();

        mb();
        nop();

	report("%s", (atomic_read(&info->cnt) == 1) &&
                        (info->irr0 != 0) && (info->irr1 == 0) && (info->irr2 == 0) &&
                        (info->isr0 == 0) && (info->isr1 != 0) && (info->isr2 == 0) &&
			(info->tmr1 == 0), msg);
}

/* Summary: 1 Case for Requirement: 140833 Expose EOI  */
/*    <1: 140833 - 27599> Local APIC_Expose EOI_001 */

/**
 * @brief case name Expose EOI
 *
 * Summary: ACRN hypervisor shall expose EOI to any VM in compliance with Chapter 10.8.5,
 *  Vol.3, SDM.
 *  EOI will be used by system software to signaling interrupt servicing Completion.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27599_expose_eoi_001(void)
{

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned int val;

        unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
        if (!(apic_base_msr & APIC_EXTD))
                return;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        report("%s - %s", atomic_read(&lapic_ipi_isr_count) == 1,
                "local_apic_rqmid_27599_expose_eoi_001", "1st IPI");

        irq_disable();
        handle_irq(vec, lapic_ipi_isr_no_eoi);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);
        mb();

        nop();
        lapic_busy_wait();
        report("%s - %s", atomic_read(&lapic_ipi_isr_count) == 2,
                "local_apic_rqmid_27599_expose_eoi_001", "2nd IPI with out EOI");

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);
        mb();
        nop();
        lapic_busy_wait();
        report("%s - %s", atomic_read(&lapic_ipi_isr_count) == 2,
                "local_apic_rqmid_27599_expose_eoi_001", "3rd IPI waiting EOI");

        eoi();

        nop();
        lapic_busy_wait();
        report("%s - %s", atomic_read(&lapic_ipi_isr_count) == 3,
		"local_apic_rqmid_27599_expose_eoi_001", "3rd IPI");
}

/* Summary: 1 Case for Requirement: 140835 Expose LAPIC ID */
/*    <1: 140835 - 27598> Local APIC_Expose LAPIC ID_001 */

/**
 * @brief case name Expose LAPIC ID
 *
 * Summary: ACRN hypervisor shall expose LAPIC ID to any VM, in compliance with Chapter
 *  10.4.6 and Chapter 10.12.8, Vol.3, SDM.
 *  VMs need APIC ID for configuring MSI data and x2APIC ID for deliver
 *  inter-processor interrupts.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27598_expose_lapic_id_001(void)
{
        const char *msg = "local_apic_rqmid_27598_expose_lapic_id_001";
        struct cpuid id0;
        struct cpuid id1;
        unsigned int id = apic_read(APIC_ID);

        id1 = cpuid(0x1);

        id0 = cpuid(0x0);
        if (id0.a >= 0xb) {
                struct cpuid id2;
                id2 = cpuid(0xb);
                if (id2.b != 0) {
                        report("%s", (id == id1.b >> 24) && (id == id2.d), msg);
                }
        }
}

/* Summary: 1 Case for Requirement: 140838 Logical x2APIC ID */
/*    <1: 140838 - 27597> Local APIC_Logical x2APIC ID_001 */

/**
 * @brief case name Logical x2APIC ID
 *
 * Summary: ACRN hypervisor shall guarantee Logical x2APIC ID = [(x2APIC ID[19:4] << 16) |
 *  (1 << x2APIC ID[3:0])], in compliance with Chapter 10.12.10.2, Vol.3, SDM.
 *  In compliance with Chapter 10.12.10.2, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27597_logical_x2apic_id_001(void)
{
	const char *msg = "local_apic_rqmid_27597_logical_x2apic_id_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 140931 Read-Only LDR in x2APIC mode */
/*    <1: 140931 - 27596> Local APIC_Read-Only LDR in x2APIC mode_001 */

static void lapic_read_only_ldr_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	wrmsr(LAPIC_MSR(APIC_LDR), LAPIC_APIC_LDR_VAL);
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

/**
 * @brief case name Read-Only LDR in x2APIC mode
 *
 * Summary: When in x2APIC mode, ACRN hypervisor shall guarantee the LDR is read-only, in
 *  compliance with Chapter 10.12.10.1, Vol.3, SDM.
 *  In compliance with Chapter 10.12.10.1, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27596_read_only_ldr_in_x2apic_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27596_read_only_ldr_in_x2apic_mode_001";
	int err = 0;

	err = test_for_exception(GP_VECTOR, lapic_read_only_ldr_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 140932 Expose SELF IPI Register in x2APIC mode */
/*    <1: 140932 - 27595> Local APIC_Expose SELF IPI Register in x2APIC mode_001 */

/**
 * @brief case name Expose SELF IPI Register in x2APIC mode
 *
 * Summary: When in x2APIC mode, ACRN hypervisor shall expose SELF IPI register, in
 *  compliance with Chapter 10.12.11, Vol.3, SDM.
 *  SELF IPIs are used extensively by some system software. The x2APIC architecture
 *  introduces a new register interface for easily configuring self IPI.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27595_expose_self_ipi_register_in_x2apic_mode_001(void)
{
        const char *msg =
                "local_apic_rqmid_27595_expose_self_ipi_register_in_x2apic_mode_001";
        const unsigned int vec = LAPIC_TEST_VEC;
        unsigned int val;

        unsigned long apic_base_msr = rdmsr(MSR_IA32_APICBASE);
        if (!(apic_base_msr & APIC_EXTD))
                return;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_write(APIC_SELF_IPI, vec);
        mb();

        nop();
        lapic_busy_wait();

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 1), msg);
}

/* Summary: 1 Case for Requirement: 140934 Write-Only SELF IPI Register */
/*    <1: 140934 - 27594> Local APIC_Write-Only SELF IPI Register_001 */

static void lapic_write_only_ipi_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	rdmsr(LAPIC_MSR(APIC_SELF_IPI));
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

/**
 * @brief case name Write-Only SELF IPI Register
 *
 * Summary: When in x2APIC mode, ACRN hypervisor shall guarantee the SELF IPI register is
 *  write-only and #GP(0) shall be inserted if VM reads this register, in compliance
 *  with Chapter 10.12.11, Vol.3, SDM.
 *  In compliance with Chapter 10.12.11, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27594_write_only_self_ipi_register_001(void)
{
	const char *msg =
		"local_apic_rqmid_27594_write_only_self_ipi_register_001";
	int err = 0;

	err = test_for_exception(GP_VECTOR, lapic_write_only_ipi_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 142455 Read-Only APIC Base */
/*    <1: 142455 - 27593> Local APIC_Read-Only APIC Base_001 */

static void lapic_read_only_apic_base_fn(void *msg)
{
        const char *report_msg = (const char *)msg;
        unsigned long val = rdmsr(MSR_IA32_APICBASE);

        if (val & APIC_EXTD)
                val &= ~(APIC_EN | APIC_EXTD);
        else
                val ^= APIC_EN;

        wrmsr(MSR_IA32_APICBASE, val);
}

/**
 * @brief case name Read-Only APIC Base
 *
 * Summary: ACRN hypervisor shall guarantee guest MSR_IA32_APICBASE is read-only.
 *  There is no demand to change the APIC base. The value of this field shall always
 *  be FEE00000H for determinacy.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27593_read_only_apic_base_001(void)
{
        static unsigned long apic_base1;
        static unsigned long apic_base2;

        static const char *msg = "local_apic_rqmid_27593_read_only_apic_base_001";
        static int err = 0;

        apic_base1 = rdmsr(MSR_IA32_APICBASE);
	mb();
        err = test_for_exception(GP_VECTOR, lapic_read_only_apic_base_fn, (void *)msg);
        apic_base2 = rdmsr(MSR_IA32_APICBASE);

        /* No gurantee the #GP */
        (void) err;

        report("%s", apic_base1 == apic_base2, msg);
}


/* Summary: 1 Case for Requirement: 142456 Read-Only Local APIC Version Register */
/*    <1: 142456 - 27592> Local APIC_Read-Only Local APIC Version Register_001 */

static void lapic_read_only_version_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	wrmsr(LAPIC_MSR(APIC_LVR), LAPIC_APIC_LVR_VAL);
	LAPIC_NO_EXEC("%s", 0, report_msg);
}
/**
 * @brief case name Read-Only Local APIC Version Register
 *
 * Summary: ACRN hypervisor shall guarantee the Local APIC Version Register is read-only.
 *  In compliance with Table 10-1 and Table 10-6, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27592_read_only_local_apic_version_register_001(void)
{
	const char *msg =
		"local_apic_rqmid_27592_read_only_local_apic_version_register_001";
	int err = 0;

	err = test_for_exception(GP_VECTOR, lapic_read_only_version_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 142457 Read-Only Remote Read Register */
/*    <1: 142457 - 27591> Local APIC_Read-Only Remote Read Register_001 */

static void lapic_read_only_remote_read_register_fn(void *msg)
{
	static unsigned int rrr1 = 0U;
	static unsigned int rrr2 = 0U;

	const char *report_msg = (const char *)msg;

	rrr1 = rdmsr(LAPIC_MSR(APIC_RRR));
	wrmsr(LAPIC_MSR(APIC_RRR), LAPIC_APIC_RRR_VAL);
	rrr2 = rdmsr(LAPIC_MSR(APIC_RRR));

	(void) rrr1;
	(void) rrr2;
	LAPIC_NO_EXEC("%s", rrr1 == rrr2, report_msg);
}

/**
 * @brief case name Read-Only Remote Read Register
 *
 * Summary: ACRN hypervisor shall guarantee the Remote Read Register is read-only, in
 *  compliance with Table 10-1 and Table 10-6, Vol.3, SDM.
 *  In compliance with Table 10-1 and Table 10-6, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27591_read_only_remote_read_register_001(void)
{

        unsigned long apic_base_status;
        const char *msg =
                "local_apic_rqmid_27591_read_only_remote_read_register_001";
        int err = 0;

        apic_base_status = rdmsr(MSR_IA32_APICBASE);
        if (!(apic_base_status & APIC_EXTD))
                return;

        err = test_for_exception(GP_VECTOR,
                lapic_read_only_remote_read_register_fn, (void *)msg);

        report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 142458 Write-Only EOI Register */
/*    <1: 142458 - 27590> Local APIC_Write-Only EOI Register_001 */

static void lapic_write_only_eoi_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	rdmsr(LAPIC_MSR(APIC_EOI));
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

/**
 * @brief case name Write-Only EOI Register
 *
 * Summary: ACRN hypervisor shall guarantee the EOI is write-only.
 *  In compliance with Table 10-1 and Table 10-6, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27590_write_only_eoi_register_001(void)
{
	const char *msg =
		"local_apic_rqmid_27590_write_only_eoi_register_001";
	int err = 0;
	err = test_for_exception(GP_VECTOR, lapic_write_only_eoi_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 142459 Read-Only ISR */
/*    <1: 142459 - 27589> Local APIC_Read-Only ISR_001 */

static void lapic_read_only_isr_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	wrmsr(LAPIC_MSR(APIC_ISR), LAPIC_APIC_ISR0_VAL);
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

/**
 * @brief case name Read-Only ISR
 *
 * Summary: ACRN hypervisor shall guarantee the ISR is read-only.
 *  In compliance with Table 10-1 and Table 10-6, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27589_read_only_isr_001(void)
{
	const char *msg = "local_apic_rqmid_27589_read_only_isr_001";
	int err = 0;
	err = test_for_exception(GP_VECTOR, lapic_read_only_isr_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 142460 Read-Only TMR */
/*    <1: 142460 - 27588> Local APIC_Read-Only TMR_001 */

static void lapic_read_only_tmr_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	wrmsr(LAPIC_MSR(APIC_TMR), LAPIC_APIC_TMR0_VAL);
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

/**
 * @brief case name Read-Only TMR
 *
 * Summary: ACRN hypervisor shall guarantee the TMR is read-only.
 *  In compliance with Table 10-1 and Table 10-6, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27588_read_only_tmr_001(void)
{
	const char *msg = "local_apic_rqmid_27588_read_only_tmr_001";
	int err = 0;
	err = test_for_exception(GP_VECTOR, lapic_read_only_tmr_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 142461 Read-Only IRR */
/*    <1: 142461 - 27587> Local APIC_Read-Only IRR_001 */

static void lapic_read_only_irr_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	wrmsr(LAPIC_MSR(APIC_IRR), LAPIC_APIC_IRR0_VAL);
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

/**
 * @brief case name Read-Only IRR
 *
 * Summary: ACRN hypervisor shall guarantee the IRR is read-only.
 *  In compliance with Table 10-1 and Table 10-6, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27587_read_only_irr_001(void)
{
	const char *msg = "local_apic_rqmid_27587_read_only_irr_001";
	int err = 0;
	err = test_for_exception(GP_VECTOR, lapic_read_only_irr_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 142462 Read-Only Error Status Register */
/*    <1: 142462 - 27586> Local APIC_Read-Only Error Status Register_001 */

static void lapic_read_only_esr_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	wrmsr(LAPIC_MSR(APIC_ESR), LAPIC_APIC_ESR_VAL);
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

/**
 * @brief case name Read-Only Error Status Register
 *
 * Summary: ACRN hypervisor shall guarantee the Error Status Register is read-only, in
 *  compliance with Table 10-1 and Table 10-6, Vol.3, SDM.
 *  In compliance with Table 10-1 and Table 10-6, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27586_read_only_error_status_register_001(void)
{
	const char *msg =
		"local_apic_rqmid_27586_read_only_error_status_register_001";
	int err = 0;
	err = test_for_exception(GP_VECTOR, lapic_read_only_esr_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 142463 Read-Only Current Count Register  */
/*    <1: 142463 - 27585> Local APIC_Read-Only Current Count Register_001 */

static void lapic_read_only_tmcct_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	wrmsr(LAPIC_MSR(APIC_TMCCT), LAPIC_APIC_TMCCT_VAL);
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

/**
 * @brief case name Read-Only Current Count Register
 *
 * Summary: ACRN hypervisor shall guarantee the Current Count Register is read-only.
 *  In compliance with Table 10-1 and Table 10-6, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27585_read_only_current_count_register_001(void)
{
	const char *msg =
		"local_apic_rqmid_27585_read_only_current_count_register_001";
	int err = 0;
	err = test_for_exception(GP_VECTOR, lapic_read_only_tmcct_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 143714 Write 1 to Reserved bit of IA32_APIC_BASE MSR */
/*    <1: 143714 - 27732> Local APIC_Write 1 to Reserved bit of IA32_APIC_BASE MSR_001 */

/**
 * @brief case name Write 1 to Reserved bit of IA32_APIC_BASE MSR
 *
 * Summary: When a vCPU attempts to write 1 to reserved bit of IA32_APIC_BASE MSR, ACRN
 *  hypervisor shall inject #GP(0), in compliance with Chapter 10.4.4, Vol.3, SDM.
 *  In compliance with Chapter 10.4.4, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27732_write_1_to_reserved_bit_of_ia32_apic_base_msr_001(void)
{
	const char *msg =
		"local_apic_rqmid_27732_write_1_to_reserved_bit_of_ia32_apic_base_msr_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 143715 Change BSP bit of IA32_APIC_BASE MSR */
/*    <1: 143715 - 27583> Local APIC_Change BSP bit of IA32_APIC_BASE MSR_001 */

/**
 * @brief case name Change BSP bit of IA32_APIC_BASE MSR
 *
 * Summary: ACRN hypervisor shall guarantee the bootstrap processor's BSP bit of
 *  IA32_APIC_BASE MSR is 1 and application processor's BSP bit of IA32_APIC_BASE MSR
 *  is 0, in compliance with Chapter 10.4.4, Vol.3, SDM.
 *  ACRN hypervisor shall guarantee the bootstrap processor's BSP bit of
 *  IA32_APIC_BASE MSR is 1 and application processor's BSP bit of IA32_APIC_BASE MSR
 *  is 0. Inject #GP(0) if changing BSP bit of bootstrap processor from 1 to 0 or
 *  changing BSP bit of application processor from 0 to 1.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27583_change_bsp_bit_of_ia32_apic_base_msr_001(void)
{
	const char *msg =
		"local_apic_rqmid_27583_change_bsp_bit_of_ia32_apic_base_msr_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 144593 Invalid state of Local APIC */
/*    <1: 144593 - 27738> Local APIC_Invalid state of Local APIC_001 */

/**
 * @brief case name Invalid state of Local APIC
 *
 * Summary: When a vCPU attempts to write MSR_IA32_APICBASE and the new MSR_IA32_APICBASE.EN is 0,
 *  ACRN hypervisor shall guarantee that the vCPU receives #GP(0).
 *  Setting MSR_IA32_APICBASE.EN to 0 and MSR_IA32_APICBASE.EXTD to 0 transfers the LAPIC
 *  into a disabled state which is not used in the current scope which is a logical
 *  partitioning scenario with a Zephyr and a Linux. Thus disabling LAPIC shall be
 *  prevented by injecting a #GP(0) to the vCPU to avoid unintended state reset.
 *  Setting MSR_IA32_APICBASE.EN to 0 and MSR_IA32_APICBASE.EXTD to 1 is an invalid state
 *  transition according to the figure 10-27, Vol 3, SDM. Also inject a #GP(0) to
 *  block the state transition.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27738_invalid_state_of_local_apic_001(void)
{
	const char *msg =
		"local_apic_rqmid_27738_invalid_state_of_local_apic_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 144594 illegal transition from disable mode to x2APIC mode */
/*    <1: 144594 - 27579> Local APIC_illegal transition from disable mode to x2APIC mode_001 */

/**
 * @brief case name illegal transition from disable mode to x2APIC mode
 *
 * Summary: If a vCPU writes IA32_APIC_BASE MSR.EN to 1, IA32_APIC_BASE MSR.EXTD to 1 and
 *  the old guest IA32_APIC_BASE MSR.EN is 0, IA32_APIC_BASE MSR.EXTD is 0, ACRN
 *  hypervisor shall guarantee #GP(0) is injected.
 *  This is illegal transition according to the figure 10-27, Vol 3, SDM. Inject
 *  #GP(0) definitely in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27579_illegal_transition_from_disable_mode_to_x2apic_mode_001(void)
{
	const char *msg =
		"local_apic_rqmid_27579_illegal_transition_from_disable_mode_to_x2apic_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 144595 illegal transition from x2APIC mode to xAPIC mode */
/*    <1: 144595 - 27578> Local APIC_illegal transition from x2APIC mode to xAPIC mode_001 */

/**
 * @brief case name illegal transition from x2APIC mode to xAPIC mode
 *
 * Summary: If a vCPU writes IA32_APIC_BASE MSR.EN to 1, IA32_APIC_BASE MSR.EXTD to 0 and
 *  the old guest IA32_APIC_BASE MSR.EN is 1, IA32_APIC_BASE MSR.EXTD is 1, ACRN
 *  hypervisor shall guarantee #GP(0) is injected.
 *  This is illegal transition according to the figure 10-27, Vol 3, SDM. Inject
 *  #GP(0) definitely in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27578_illegal_transition_from_x2apic_mode_to_xapic_mode_001(void)
{
	const char *msg =
		"local_apic_rqmid_27578_illegal_transition_from_x2apic_mode_to_xapic_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 144596 Inject #GP(0) when access to Local APIC register in xAPIC mode */
/*    <1: 144596 - 27577> Local APIC_Inject #GP(0) when access to Local APIC register in xAPIC mode_001 */

/**
 * @brief case name Inject #GP(0) when access to Local APIC register in xAPIC mode
 *
 * Summary: If a vCPU reads or writes xAPIC mode Local APIC register in Table 10-1, Vol 3,
 *  SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  xAPIC mode is not supported. When access to Local APIC register in xAPIC mode,
 *  #GP(0) shall be injected definitely.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27577_inject_gp0_when_access_to_local_apic_register_in_xapic_mode_001(void)
{
	const char *msg =
		"local_apic_rqmid_27577_inject_gp0_when_access_to_local_apic_register_in_xapic_mode_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 144597 Inject #GP(0) when wrmsr x2APIC read only register */
/*    <1: 144597 - 27576> Local APIC_Inject #GP(0) when wrmsr x2APIC read only register_001 */

struct x2apic_ro_info_s {
	unsigned int reg;
	unsigned long val;
	const char *msg;
	const char *reg_str;
};

static void lapic_read_only_all_x2apic_fn(void *msg)
{
	const struct x2apic_ro_info_s *info = (struct x2apic_ro_info_s *)msg;

	const char *report_msg = (const char *)info->msg;
	const char *reg_str = (const char *)info->reg_str;
	wrmsr(info->reg, info->val);
	LAPIC_NO_EXEC("%s - %s", 0, report_msg, reg_str);
}

/**
 * @brief case name Inject #GP(0) when wrmsr x2APIC read only register
 *
 * Summary: If a vCPU attempts to write a LAPIC register and the LAPIC register is
 *  read-only, ACRN hypervisor shall guarantee that the vCPU receives #GP(0).
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27576_inject_gp0_when_wrmsr_x2apic_read_only_register_001(void)
{
	static struct x2apic_ro_info_s ro_info_arr[] = {
		{ LAPIC_MSR(APIC_ID), LAPIC_APIC_ID_VAL, "",	"APIC_ID"  },
		{ LAPIC_MSR(APIC_LVR), LAPIC_APIC_LVR_VAL, "",  "APIC_LVR" },
		{ LAPIC_MSR(APIC_PROCPRI), LAPIC_APIC_PPR_VAL, "",  "APIC_PPR" },
		{ LAPIC_MSR(APIC_LDR), LAPIC_APIC_LDR_VAL, "",  "APIC_LDR" },
		{ LAPIC_MSR(APIC_ISR + 0x0),  LAPIC_APIC_ISR0_VAL, "", "APIC_ISR0" },
		{ LAPIC_MSR(APIC_ISR + 0x10), LAPIC_APIC_ISR1_VAL, "", "APIC_ISR1" },
		{ LAPIC_MSR(APIC_ISR + 0x20), LAPIC_APIC_ISR2_VAL, "", "APIC_ISR2" },
		{ LAPIC_MSR(APIC_ISR + 0x30), LAPIC_APIC_ISR3_VAL, "", "APIC_ISR3" },
		{ LAPIC_MSR(APIC_ISR + 0x40), LAPIC_APIC_ISR4_VAL, "", "APIC_ISR4" },
		{ LAPIC_MSR(APIC_ISR + 0x50), LAPIC_APIC_ISR5_VAL, "", "APIC_ISR5" },
		{ LAPIC_MSR(APIC_ISR + 0x60), LAPIC_APIC_ISR6_VAL, "", "APIC_ISR6" },
		{ LAPIC_MSR(APIC_ISR + 0x70), LAPIC_APIC_ISR7_VAL, "", "APIC_ISR7" },
		{ LAPIC_MSR(APIC_TMR + 0x0),  LAPIC_APIC_TMR0_VAL, "", "APIC_TMR0" },
		{ LAPIC_MSR(APIC_TMR + 0x10), LAPIC_APIC_TMR1_VAL, "", "APIC_TMR1" },
		{ LAPIC_MSR(APIC_TMR + 0x20), LAPIC_APIC_TMR2_VAL, "", "APIC_TMR2" },
		{ LAPIC_MSR(APIC_TMR + 0x30), LAPIC_APIC_TMR3_VAL, "", "APIC_TMR3" },
		{ LAPIC_MSR(APIC_TMR + 0x40), LAPIC_APIC_TMR4_VAL, "", "APIC_TMR4" },
		{ LAPIC_MSR(APIC_TMR + 0x50), LAPIC_APIC_TMR5_VAL, "", "APIC_TMR5" },
		{ LAPIC_MSR(APIC_TMR + 0x60), LAPIC_APIC_TMR6_VAL, "", "APIC_TMR6" },
		{ LAPIC_MSR(APIC_TMR + 0x70), LAPIC_APIC_TMR7_VAL, "", "APIC_TMR7" },
		{ LAPIC_MSR(APIC_IRR + 0x0),  LAPIC_APIC_IRR0_VAL, "", "APIC_IRR0" },
		{ LAPIC_MSR(APIC_IRR + 0x10), LAPIC_APIC_IRR1_VAL, "", "APIC_IRR1" },
		{ LAPIC_MSR(APIC_IRR + 0x20), LAPIC_APIC_IRR2_VAL, "", "APIC_IRR2" },
		{ LAPIC_MSR(APIC_IRR + 0x30), LAPIC_APIC_IRR3_VAL, "", "APIC_IRR3" },
		{ LAPIC_MSR(APIC_IRR + 0x40), LAPIC_APIC_IRR4_VAL, "", "APIC_IRR4" },
		{ LAPIC_MSR(APIC_IRR + 0x50), LAPIC_APIC_IRR5_VAL, "", "APIC_IRR5" },
		{ LAPIC_MSR(APIC_IRR + 0x60), LAPIC_APIC_IRR6_VAL, "", "APIC_IRR6" },
		{ LAPIC_MSR(APIC_IRR + 0x70), LAPIC_APIC_IRR7_VAL, "", "APIC_IRR7" },
		{ LAPIC_MSR(APIC_TMCCT), LAPIC_APIC_TMCCT_VAL, "", "APIC_TMCCT" },
	};
	static const int nr = sizeof(ro_info_arr)/sizeof(*ro_info_arr);
	static const char *msg =
		"local_apic_rqmid_27576_inject_gp0"
		"_when_wrmsr_x2apic_read_only_register_001";
	static const char *reg_str = "unknown";

	static int err;
	static int i;

	for(i = 0; i < nr; i += 1) {
		err = 0;

		ro_info_arr[i].msg = msg;
		reg_str =ro_info_arr[i].reg_str;

		err = test_for_exception(GP_VECTOR,
			lapic_read_only_all_x2apic_fn, (void *)&ro_info_arr[i]);
		report("%s - %s", err != 0, msg, reg_str);
	}
}

/* Summary: 1 Case for Requirement: 144598 Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register */
/*    <1: 144598 - 27575> Local APIC_Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register_001 */

struct x2apic_reserved_bits_info_s {
        unsigned addr;
        unsigned int start;
        unsigned int stop;
        const char *msg;
        const char *reg_str;
};
static void lapic_x2apic_write_reserved_to_1(void *msg)
{
        const struct x2apic_reserved_bits_info_s *info =
                (struct x2apic_reserved_bits_info_s *)msg;
        const char *report_msg = info->msg;
        const char *reg_str = info->reg_str;

        unsigned long val = ((0x1UL << (info->stop + 1)) - 1) &
                (~((0x1UL << info->start) - 1));
        wrmsr(info->addr, val);
        LAPIC_NO_EXEC("%s - %s", 0, report_msg, reg_str);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27575_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_001(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_TASKPRI),
                LAPIC_RESERVED_BIT(8),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_TPR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,

 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None

 *
 * @retval None
 *
 */
void local_apic_rqmid_31389_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_002(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_SPIV),
                LAPIC_RESERVED_BIT(10),
                LAPIC_RESERVED_BIT(11),
                __func__,
                "APIC_SPIV",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31395_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_003(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_SPIV),
                LAPIC_RESERVED_BIT(13),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_SPIV",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31396_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_004(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_ESR),
                LAPIC_RESERVED_BIT(0),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_ESR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31397_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_005(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTCMCI),
                LAPIC_RESERVED_BIT(17),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_LVTCMCI",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31399_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_006(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTCMCI),
                LAPIC_RESERVED_BIT(13),
                LAPIC_RESERVED_BIT(15),
                __func__,
                "APIC_LVTCMCI",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31400_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_007(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTCMCI),
                LAPIC_RESERVED_BIT(11),
                LAPIC_RESERVED_BIT(11),
                __func__,
                "APIC_LVTCMCI",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31401_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_008(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_ICR),
                LAPIC_RESERVED_BIT(20),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_ICR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31402_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_009(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_ICR),
                LAPIC_RESERVED_BIT(16),
                LAPIC_RESERVED_BIT(17),
                __func__,
                "APIC_ICR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31403_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_010(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_ICR),
                LAPIC_RESERVED_BIT(12),
                LAPIC_RESERVED_BIT(13),
                __func__,
                "APIC_ICR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31404_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_011(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTT),
                LAPIC_RESERVED_BIT(19),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_LVTT",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31405_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_012(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTT),
                LAPIC_RESERVED_BIT(13),
                LAPIC_RESERVED_BIT(15),
                __func__,
                "APIC_LVTT",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31406_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_013(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTT),
                LAPIC_RESERVED_BIT(8),
                LAPIC_RESERVED_BIT(11),
                __func__,
                "APIC_LVTT",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31407_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_014(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTTHMR),
                LAPIC_RESERVED_BIT(17),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_LVTTHMR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31408_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_015(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTTHMR),
                LAPIC_RESERVED_BIT(13),
                LAPIC_RESERVED_BIT(15),
                __func__,
                "APIC_LVTTHMR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}
/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31409_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_016(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTTHMR),
                LAPIC_RESERVED_BIT(11),
                LAPIC_RESERVED_BIT(11),
                __func__,
                "APIC_LVTTHMR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31410_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_017(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTPC),
                LAPIC_RESERVED_BIT(17),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_LVTPC",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31411_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_018(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTPC),
                LAPIC_RESERVED_BIT(13),
                LAPIC_RESERVED_BIT(15),
                __func__,
                "APIC_LVTPC",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31412_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_019(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTPC),
                LAPIC_RESERVED_BIT(11),
                LAPIC_RESERVED_BIT(11),
                __func__,
                "APIC_LVTPC",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31413_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_020(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVT0),
                LAPIC_RESERVED_BIT(17),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_LVT0",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31414_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_021(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVT0),
                LAPIC_RESERVED_BIT(11),
                LAPIC_RESERVED_BIT(11),
                __func__,
                "APIC_LVT0",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31415_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_022(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVT1),
                LAPIC_RESERVED_BIT(17),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_LVT1",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31416_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_023(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVT1),
                LAPIC_RESERVED_BIT(11),
                LAPIC_RESERVED_BIT(11),
                __func__,
                "APIC_LVT1",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31417_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_024(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTERR),
                LAPIC_RESERVED_BIT(17),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_LVTERR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31418_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_025(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTERR),
                LAPIC_RESERVED_BIT(13),
                LAPIC_RESERVED_BIT(15),
                __func__,
                "APIC_LVTERR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31419_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_026(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_LVTERR),
                LAPIC_RESERVED_BIT(8),
                LAPIC_RESERVED_BIT(11),
                __func__,
                "APIC_LVTERR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/**
 * @brief case name Inject #GP(0) when wrmsr attempts to set a reserved bit to 1 in a read/write register
 *
 * Summary: If a vCPU writes reserved bit of x2APIC mode Local APIC registers in Table 10-6,
 *  Vol 3, SDM, ACRN hypervisor shall guarantee #GP(0) is injected.
 *  According to the SDM, inject #GP(0) in this case.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_31420_inject_gp0_when_wrmsr_attempts_to_set_a_reserved_bit_to_1_in_a_read_write_register_027(void)
{
        static const char *msg = __func__;
        static struct x2apic_reserved_bits_info_s info_arr = {
                LAPIC_MSR(APIC_TDCR),
                LAPIC_RESERVED_BIT(4),
                LAPIC_RESERVED_BIT(31),
                __func__,
                "APIC_TDCR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_x2apic_write_reserved_to_1, (void *)&info_arr);
        report("%s", err != 0, msg);
}

/* Summary: 1 Case for Requirement: 144599 Inject #GP(0) when rdmsr causes #GP(0) for write-only registers */
/*    <1: 144599 - 27810> Local APIC_Inject #GP(0) when rdmsr causes #GP(0) for write-only registers_001 */

struct x2apic_wo_info_s {
	unsigned int reg;
	unsigned long val;
	const char *msg;
	const char *reg_str;
};

static void lapic_write_only_all_x2apic_fn(void *msg)
{
	struct x2apic_wo_info_s *info = (struct x2apic_wo_info_s *)msg;

	const char *report_msg = (const char *)info->msg;
	const char *reg_str = (const char *)info->reg_str;
	info->val = rdmsr(info->reg);
	LAPIC_NO_EXEC("%s - %s", 0, report_msg, reg_str);
}

void local_apic_rqmid_27810_inject_gp0_when_rdmsr_causes_gp0_for_write_only_registers_001(void)
{
        static const char *msg = __func__;
	static struct x2apic_wo_info_s wo_info = {
                LAPIC_MSR(APIC_EOI),
                LAPIC_APIC_EOI_VAL,
                __func__,
                "APIC_TDCR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_write_only_all_x2apic_fn, (void *)&wo_info);
        report("%s", err != 0, msg);
}
void local_apic_rqmid_27810_inject_gp0_when_rdmsr_causes_gp0_for_write_only_registers_002(void)
{
        static const char *msg = __func__;
	static struct x2apic_wo_info_s wo_info = {
                LAPIC_MSR(APIC_SELF_IPI),
                LAPIC_APIC_SELF_IPI_VAL,
                __func__,
                "APIC_TDCR",
        };
        static int err = 0;

        err = test_for_exception(GP_VECTOR, lapic_write_only_all_x2apic_fn, (void *)&wo_info);
        report("%s", err != 0, msg);
}

/* Summary: 2 Case for Requirement: 144609 LVT interrupt pending  */
/*    <1: 144609 - 27574> Local APIC_LVT interrupt pending_001 */

/**
 * @brief case name LVT interrupt pending
 *
 * Summary: If a LVT inteterrput has been delivered to the processor core but has not yet
 *  received the first INTA ACK, ACRN hypervisor shall guarantee Delivery Status bit
 *  in LVT to be set to 1.
 *  According to the Chapter 10.5.1 and 10.5.5, Vol 3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27574_lvt_interrupt_pending_001(void)
{
	const char *msg = "local_apic_rqmid_27574_lvt_interrupt_pending_001";
	report("deprecated: %s", 0, msg);
}

/*    <2: 144609 - 27573> Local APIC_LVT interrupt pending_002 */

/**
 * @brief case name LVT interrupt pending
 *
 * Summary: If a LVT inteterrput has been delivered to the processor core but has not yet
 *  received the first INTA ACK, ACRN hypervisor shall guarantee Delivery Status bit
 *  in LVT to be set to 1.
 *  According to the Chapter 10.5.1 and 10.5.5, Vol 3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27573_lvt_interrupt_pending_002(void)
{
	const char *msg = "local_apic_rqmid_27573_lvt_interrupt_pending_002";
	report("deprecated: %s", 0, msg);
}

/* Summary: 14 Case for Requirement: 144610 illegal vector in LVT register */
/*    <1: 144610 - 27571> Local APIC_illegal vector in LVT register_001 */

// BUG - 144610 - Received Illegal Vecotr
/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27571_illegal_vector_in_lvt_register_001(void)
{
        const char *msg = "local_apic_rqmid_27571_illegal_vector_in_lvt_register_001";
        const char *reg_str = "APIC_LVTT";
        unsigned reg = APIC_LVTT;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
}

/*    <2: 144610 - 27569> Local APIC_illegal vector in LVT register_002 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27569_illegal_vector_in_lvt_register_002(void)
{
        const char *msg = "local_apic_rqmid_27569_illegal_vector_in_lvt_register_002";
        const char *reg_str = "APIC_LVTCMCI";
        unsigned reg = APIC_LVTCMCI;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
}

/*    <3: 144610 - 27567> Local APIC_illegal vector in LVT register_003 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27567_illegal_vector_in_lvt_register_003(void)
{
        const char *msg = "local_apic_rqmid_27567_illegal_vector_in_lvt_register_003";
        const char *reg_str = "APIC_LVTTHMR";
        unsigned reg = APIC_LVTTHMR;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
}

/*    <4: 144610 - 27566> Local APIC_illegal vector in LVT register_004 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27566_illegal_vector_in_lvt_register_004(void)
{
        const char *msg = "local_apic_rqmid_27566_illegal_vector_in_lvt_register_004";
        const char *reg_str = "APIC_LVTPC";
        unsigned reg = APIC_LVTPC;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
}

/*    <5: 144610 - 27558> Local APIC_illegal vector in LVT register_005 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27558_illegal_vector_in_lvt_register_005(void)
{
        const char *msg = "local_apic_rqmid_27558_illegal_vector_in_lvt_register_005";
        const char *reg_str = "APIC_LVT0";
        unsigned reg = APIC_LVT0;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
}

/*    <6: 144610 - 27565> Local APIC_illegal vector in LVT register_006 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27565_illegal_vector_in_lvt_register_006(void)
{
        const char *msg = "local_apic_rqmid_27565_illegal_vector_in_lvt_register_006";
        const char *reg_str = "APIC_LVT1";
        unsigned reg = APIC_LVT1;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
}

/*    <7: 144610 - 27572> Local APIC_illegal vector in LVT register_007 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27572_illegal_vector_in_lvt_register_007(void)
{
        const char *msg = "local_apic_rqmid_27572_illegal_vector_in_lvt_register_007";
        const char *reg_str = "APIC_LVTERR";
        unsigned reg = APIC_LVTERR;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
}

/*    <8: 144610 - 27557> Local APIC_illegal vector in LVT register_008 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27557_illegal_vector_in_lvt_register_008(void)
{
	/* Full Coverage
	 *
	 * The Illegal Vector is from 0 to 15(including)
	 * So, now, we just use 2 case for each LVT Register
	 *
	 * (1) signle 0 vector
	 * (2) full coverage from 1 to 15
	 * for there is no rule to select one, or all to Test.
	 *
	 * Basically, I think, The fully coverage is need.
	 * if cannot use for-loop, you need to divide this to 15 different case
	 * for each LVT.
	 *
	 */
        const char *msg = "local_apic_rqmid_27557_illegal_vector_in_lvt_register_008";
        const char *reg_str = "APIC_LVTT";
        unsigned reg = APIC_LVTT;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

	LAPIC_ILLEGAL_VECTOR_LOOP_START(vec,LAPIC_TEST_INVALID_MAX_VEC)
        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
	LAPIC_ILLEGAL_VECTOR_LOOP_END
}

/*    <9: 144610 - 27570> Local APIC_illegal vector in LVT register_009 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27570_illegal_vector_in_lvt_register_009(void)
{
	/* Full Coverage
	 *
	 * The Illegal Vector is from 0 to 15(including)
	 * So, now, we just use 2 case for each LVT Register
	 *
	 * (1) signle 0 vector
	 * (2) full coverage from 1 to 15
	 * for there is no rule to select one, or all to Test.
	 *
	 * Basically, I think, The fully coverage is need.
	 * if cannot use for-loop, you need to divide this to 15 different case
	 * for each LVT.
	 *
	 */
        const char *msg = "local_apic_rqmid_27570_illegal_vector_in_lvt_register_009";
        const char *reg_str = "APIC_LVTCMCI";
        unsigned reg = APIC_LVTCMCI;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

	LAPIC_ILLEGAL_VECTOR_LOOP_START(vec,LAPIC_TEST_INVALID_MAX_VEC)
        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
	LAPIC_ILLEGAL_VECTOR_LOOP_END
}

/*    <10: 144610 - 27568> Local APIC_illegal vector in LVT register_010 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27568_illegal_vector_in_lvt_register_010(void)
{
	/* Full Coverage
	 *
	 * The Illegal Vector is from 0 to 15(including)
	 * So, now, we just use 2 case for each LVT Register
	 *
	 * (1) signle 0 vector
	 * (2) full coverage from 1 to 15
	 * for there is no rule to select one, or all to Test.
	 *
	 * Basically, I think, The fully coverage is need.
	 * if cannot use for-loop, you need to divide this to 15 different case
	 * for each LVT.
	 *
	 */
        const char *msg = "local_apic_rqmid_27568_illegal_vector_in_lvt_register_010";
        const char *reg_str = "APIC_LVTTHMR";
        unsigned reg = APIC_LVTTHMR;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

	LAPIC_ILLEGAL_VECTOR_LOOP_START(vec,LAPIC_TEST_INVALID_MAX_VEC)
        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
	LAPIC_ILLEGAL_VECTOR_LOOP_END
}

/*    <11: 144610 - 27564> Local APIC_illegal vector in LVT register_011 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27564_illegal_vector_in_lvt_register_011(void)
{
	/* Full Coverage
	 *
	 * The Illegal Vector is from 0 to 15(including)
	 * So, now, we just use 2 case for each LVT Register
	 *
	 * (1) signle 0 vector
	 * (2) full coverage from 1 to 15
	 * for there is no rule to select one, or all to Test.
	 *
	 * Basically, I think, The fully coverage is need.
	 * if cannot use for-loop, you need to divide this to 15 different case
	 * for each LVT.
	 *
	 */
        const char *msg = "local_apic_rqmid_27564_illegal_vector_in_lvt_register_011";
        const char *reg_str = "APIC_LVTPC";
        unsigned reg = APIC_LVTPC;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

	LAPIC_ILLEGAL_VECTOR_LOOP_START(vec,LAPIC_TEST_INVALID_MAX_VEC)
        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
	LAPIC_ILLEGAL_VECTOR_LOOP_END
}

/*    <12: 144610 - 27561> Local APIC_illegal vector in LVT register_012 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27561_illegal_vector_in_lvt_register_012(void)
{
	/* Full Coverage
	 *
	 * The Illegal Vector is from 0 to 15(including)
	 * So, now, we just use 2 case for each LVT Register
	 *
	 * (1) signle 0 vector
	 * (2) full coverage from 1 to 15
	 * for there is no rule to select one, or all to Test.
	 *
	 * Basically, I think, The fully coverage is need.
	 * if cannot use for-loop, you need to divide this to 15 different case
	 * for each LVT.
	 *
	 */
        const char *msg = "local_apic_rqmid_27561_illegal_vector_in_lvt_register_012";
        const char *reg_str = "APIC_LVT0";
        unsigned reg = APIC_LVT0;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

	LAPIC_ILLEGAL_VECTOR_LOOP_START(vec,LAPIC_TEST_INVALID_MAX_VEC)
        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
	LAPIC_ILLEGAL_VECTOR_LOOP_END
}

/*    <13: 144610 - 27560> Local APIC_illegal vector in LVT register_013 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27560_illegal_vector_in_lvt_register_013(void)
{
	/* Full Coverage
	 *
	 * The Illegal Vector is from 0 to 15(including)
	 * So, now, we just use 2 case for each LVT Register
	 *
	 * (1) signle 0 vector
	 * (2) full coverage from 1 to 15
	 * for there is no rule to select one, or all to Test.
	 *
	 * Basically, I think, The fully coverage is need.
	 * if cannot use for-loop, you need to divide this to 15 different case
	 * for each LVT.
	 *
	 */
        const char *msg = "local_apic_rqmid_27560_illegal_vector_in_lvt_register_013";
        const char *reg_str = "APIC_LVT1";
        unsigned reg = APIC_LVT1;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

	LAPIC_ILLEGAL_VECTOR_LOOP_START(vec,LAPIC_TEST_INVALID_MAX_VEC)
        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
	LAPIC_ILLEGAL_VECTOR_LOOP_END
}

/*    <14: 144610 - 27559> Local APIC_illegal vector in LVT register_014 */

/**
 * @brief case name illegal vector in LVT register
 *
 * Summary: When a vCPU writes LAPIC LVT register and the new guest LAPIC LVT register [bit
 *  7:0] is less than 10H, ACRN hypervisor shall guarantee that the guest LAPIC of
 *  the vCPU detects a received illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27559_illegal_vector_in_lvt_register_014(void)
{
	/* Full Coverage
	 *
	 * The Illegal Vector is from 0 to 15(including)
	 * So, now, we just use 2 case for each LVT Register
	 *
	 * (1) signle 0 vector
	 * (2) full coverage from 1 to 15
	 * for there is no rule to select one, or all to Test.
	 *
	 * Basically, I think, The fully coverage is need.
	 * if cannot use for-loop, you need to divide this to 15 different case
	 * for each LVT.
	 *
	 */
        const char *msg = "local_apic_rqmid_27559_illegal_vector_in_lvt_register_014";
        const char *reg_str = "APIC_LVTERR";
        unsigned reg = APIC_LVTERR;
        unsigned long vec = LAPIC_TEST_INVALID_VEC1;
        volatile unsigned long val;
        unsigned long esr;

	LAPIC_ILLEGAL_VECTOR_LOOP_START(vec,LAPIC_TEST_INVALID_MAX_VEC)
        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        val = apic_read(reg);
        val &= ~APIC_VECTOR_MASK;
        val &= LAPIC_REG_MASK;
        val &= ~APIC_LVT_MASKED;

        val |= vec;
        if (apic_read(APIC_ESR) != 0UL)
                apic_write(APIC_ESR, 0U);
        mb();

        apic_write(reg, val);
        mb();
        esr = apic_read(APIC_ESR);
        report("%s - %s", (esr & (0x1UL << 6)) != 0UL, msg, reg_str);
	LAPIC_ILLEGAL_VECTOR_LOOP_END
}

/* Summary: 2 Case for Requirement: 144611 Write the DCR */
/*    <1: 144611 - 27555> Local APIC_Write the DCR_001 */

extern void asm_fixed_delay(void);
asm (
        ".text                          \n\t"
        ".global asm_fixed_delay	\n\t"
        "asm_fixed_delay:		\n\t"
        "mov $10000000, %rcx           \n\t"
        "1: dec %rcx                    \n\t"
        "jnz 1b                         \n\t"
        "ret                            \n\t"
);

/**
 * @brief case name Write the DCR
 *
 * Summary: If a vCPU write a value to the DCR, ACRN hypervisor shall guarantee CCR
 *  count-down restart and the value in DCR is immediately used.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27555_write_the_dcr_001(void)
{
	const char *msg = "local_apic_rqmid_27555_write_the_dcr_001";
	const unsigned vec = LAPIC_TEST_INVALID_VEC;
	volatile unsigned val;
	volatile unsigned before1;
	volatile unsigned now1;
	volatile unsigned now2;

	unsigned dcr = apic_read(APIC_TDCR);

	wrmsr(MSR_IA32_TSCDEADLINE, 0UL);
	apic_write(APIC_TMICT, 0U);

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_LVTT);
	val &= ~APIC_VECTOR_MASK;
	val |= vec;
	val |= APIC_LVT_MASKED;


	val &= ~APIC_LVT_TIMER_MASK;
        val |= APIC_LVT_TIMER_PERIODIC;

	val &= LAPIC_REG_MASK;
	apic_write(APIC_LVTT, val);
	mb();

	apic_write(APIC_TMICT, ~0U);
	mb();

	before1 = apic_read(APIC_TMCCT);
	mb();
	asm_fixed_delay();
	now1 = apic_read(APIC_TMCCT);
	mb();


	apic_write(APIC_TDCR, 0x0A);

	nop();
	now2 = apic_read(APIC_TMCCT);
	mb();

	apic_write(APIC_TDCR, dcr);
	report("%s", (before1 < ~0U) && (now1 < before1) && (now2 <= ~0U) && (now2 > now1), msg);
}

/*    <2: 144611 - 27554> Local APIC_Write the DCR_002 */

/**
 * @brief case name Write the DCR
 *
 * Summary: If a vCPU write a value to the DCR, ACRN hypervisor shall guarantee CCR
 *  count-down restart and the value in DCR is immediately used.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27554_write_the_dcr_002(void)
{
	const char *msg = "local_apic_rqmid_27554_write_the_dcr_002";
	report("deprecated: %s", 0, msg);
}

/* Summary: 2 Case for Requirement: 144612 illegal vector in ICR */
/*    <1: 144612 - 27805> Local APIC_illegal vector in ICR_001 */

/**
 * @brief case name illegal vector in ICR
 *
 * Summary: When a vCPU writes LAPIC ICR and the new guest LAPIC ICR [bit 7:0] is less than
 *  10H, ACRN hypervisor shall guarantee that the guest LAPIC of the vCPU detects a
 *  send illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27805_illegal_vector_in_icr_001(void)
{
        const char *msg = "local_apic_rqmid_27805_illegal_vector_in_icr_001";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_INVALID_VEC;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);
        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) &&
                ((esr & (0x1UL << 5)) != 0UL), msg);
}

/*    <2: 144612 - 27553> Local APIC_illegal vector in ICR_002 */

/**
 * @brief case name illegal vector in ICR
 *
 * Summary: When a vCPU writes LAPIC ICR and the new guest LAPIC ICR [bit 7:0] is less than
 *  10H, ACRN hypervisor shall guarantee that the guest LAPIC of the vCPU detects a
 *  send illegal vector error.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27553_illegal_vector_in_icr_002(void)
{
	const char *msg = "local_apic_rqmid_27553_illegal_vector_in_icr_002";
	report("deprecated: %s", 0, msg);
}

/* Summary: 2 Case for Requirement: 145244 illegal vector in SVR */
/*    <1: 145244 - 27552> Local APIC_illegal vector in SVR_001 */

/**
 * @brief case name illegal vector in SVR
 *
 * Summary: If an illegal vector is set in SVR, ACRN hypervisor shall guarantee no ESR bit
 *  to be set.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27552_illegal_vector_in_svr_001(void)
{
	const char *msg = "local_apic_rqmid_27552_illegal_vector_in_svr_001";
	report("deprecated: %s", 0, msg);
}

/*    <2: 145244 - 27551> Local APIC_illegal vector in SVR_002 */

/**
 * @brief case name illegal vector in SVR
 *
 * Summary: If an illegal vector is set in SVR, ACRN hypervisor shall guarantee no ESR bit
 *  to be set.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27551_illegal_vector_in_svr_002(void)
{
	const char *msg = "local_apic_rqmid_27551_illegal_vector_in_svr_002";
	report("deprecated: %s", 0, msg);
}

/* Summary: 2 Case for Requirement: 146049 expose IA32_APIC_BASE */
/*    <1: 146049 - 27550> Local APIC_expose IA32_APIC_BASE_001 */

/**
 * @brief case name expose IA32_APIC_BASE
 *
 * Summary: ACRN hypervisor shall expose IA32_APIC_BASE to any VM, in compliance with
 *  Chapter 10.4.4, Vol.3 and Chapter 2.1, Vol.4 SDM.
 *  MSR_IA32_APICBASE is used by configuring LAPIC.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27550_expose_ia32_apic_base_001(void)
{
	const char *msg = "local_apic_rqmid_27550_expose_ia32_apic_base_001";
	report("deprecated: %s", 0, msg);
}

/*    <2: 146049 - 27549> Local APIC_expose IA32_APIC_BASE_002 */

/**
 * @brief case name expose IA32_APIC_BASE
 *
 * Summary: ACRN hypervisor shall expose IA32_APIC_BASE to any VM, in compliance with
 *  Chapter 10.4.4, Vol.3 and Chapter 2.1, Vol.4 SDM.
 *  MSR_IA32_APICBASE is used by configuring LAPIC.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27549_expose_ia32_apic_base_002(void)
{
	const char *msg = "local_apic_rqmid_27549_expose_ia32_apic_base_002";
	report("deprecated: %s", 0, msg);
}

/* Summary: 1 Case for Requirement: 146050 APIC State transitions */
/*    <1: 146050 - 27734> Local APIC_APIC State transitions_001 */

/**
 * @brief case name APIC State transitions
 *
 * Summary: ACRN hypervisor shall expose APIC State transitions to any VM, in compliance
 *  with Chapter 10.12.5, Vol.3 SDM.
 *  In compliance with Chapter 10.12.5, Vol.3 SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27734_apic_state_transitions_001(void)
{
	const char *msg = "local_apic_rqmid_27734_apic_state_transitions_001";
	report("deprecated: %s", 0, msg);
}

/* Summary: 2 Case for Requirement: 146051 State reset when entering disabled mode */
/*    <1: 146051 - 27548> Local APIC_State reset when entering disabled mode_001 */

/**
 * @brief case name State reset when entering disabled mode
 *
 * Summary: When LAPIC entering disabled mode from xAPIC mode or x2APIC mode, ACRN
 *  hypervisor shall guarantee the the states of lapic need be reset. Keep the
 *  behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27548_state_reset_when_entering_disabled_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27548_state_reset_when_entering_disabled_mode_001";
	report("deprecated: %s", 0, msg);
}

/*    <2: 146051 - 27547> Local APIC_State reset when entering disabled mode_002 */

/**
 * @brief case name State reset when entering disabled mode
 *
 * Summary: When LAPIC entering disabled mode from xAPIC mode or x2APIC mode, ACRN
 *  hypervisor shall guarantee the the states of lapic need be reset. Keep the
 *  behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27547_state_reset_when_entering_disabled_mode_002(void)
{
	const char *msg = "local_apic_rqmid_27547_state_reset_when_entering_disabled_mode_002";
	report("deprecated: %s", 0, msg);
}

/* Summary: 14 Case for Requirement: 146052 mask bit in LVT when Software re-enabling  */
/*    <1: 146052 - 27544> Local APIC_mask bit in LVT when Software re-enabling_001 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27544_mask_bit_in_lvt_when_software_re_enabling_001(void)
{
        const char *msg =
		"local_apic_rqmid_27544_mask_bit_in_lvt_when_software_re_enabling_001";
	const unsigned reg = APIC_LVTT;
	const char *reg_str = "APIC_LVTT";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val |= APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED,
		msg, "set APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED, msg, reg_str);
}

/*    <2: 146052 - 27543> Local APIC_mask bit in LVT when Software re-enabling_002 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27543_mask_bit_in_lvt_when_software_re_enabling_002(void)
{
        const char *msg =
		"local_apic_rqmid_27543_mask_bit_in_lvt_when_software_re_enabling_002";
	const unsigned reg = APIC_LVTCMCI;
	const char *reg_str = "APIC_LVTCMCI";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val |= APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED,
		msg, "set APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED, msg, reg_str);
}
/*    <3: 146052 - 27542> Local APIC_mask bit in LVT when Software re-enabling_003 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27542_mask_bit_in_lvt_when_software_re_enabling_003(void)
{
        const char *msg =
		"local_apic_rqmid_27542_mask_bit_in_lvt_when_software_re_enabling_003";
	const unsigned reg = APIC_LVTTHMR;
	const char *reg_str = "APIC_LVTTHMR";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val |= APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED,
		msg, "set APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED, msg, reg_str);
}

/*    <4: 146052 - 27541> Local APIC_mask bit in LVT when Software re-enabling_004 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27541_mask_bit_in_lvt_when_software_re_enabling_004(void)
{
        const char *msg =
		"local_apic_rqmid_27541_mask_bit_in_lvt_when_software_re_enabling_004";
	const unsigned reg = APIC_LVTPC;
	const char *reg_str = "APIC_LVTPC";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val |= APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED,
		msg, "set APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED, msg, reg_str);
}

/*    <5: 146052 - 27540> Local APIC_mask bit in LVT when Software re-enabling_005 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27540_mask_bit_in_lvt_when_software_re_enabling_005(void)
{
        const char *msg =
		"local_apic_rqmid_27540_mask_bit_in_lvt_when_software_re_enabling_005";
	const unsigned reg = APIC_LVT0;
	const char *reg_str = "APIC_LVT0";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val |= APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED,
		msg, "set APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED, msg, reg_str);
}

/*    <6: 146052 - 27539> Local APIC_mask bit in LVT when Software re-enabling_006 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27539_mask_bit_in_lvt_when_software_re_enabling_006(void)
{
        const char *msg =
		"local_apic_rqmid_27539_mask_bit_in_lvt_when_software_re_enabling_006";
	const unsigned reg = APIC_LVT1;
	const char *reg_str = "APIC_LVT1";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val |= APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED,
		msg, "set APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED, msg, reg_str);
}

/*    <7: 146052 - 27538> Local APIC_mask bit in LVT when Software re-enabling_007 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27538_mask_bit_in_lvt_when_software_re_enabling_007(void)
{
        const char *msg =
		"local_apic_rqmid_27538_mask_bit_in_lvt_when_software_re_enabling_007";
	const unsigned reg = APIC_LVTERR;
	const char *reg_str = "APIC_LVTERR";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val |= APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED,
		msg, "set APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == APIC_LVT_MASKED, msg, reg_str);
}

/*    <8: 146052 - 27537> Local APIC_mask bit in LVT when Software re-enabling_008 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27537_mask_bit_in_lvt_when_software_re_enabling_008(void)
{
        const char *msg =
		"local_apic_rqmid_27537_mask_bit_in_lvt_when_software_re_enabling_008";
	const unsigned reg = APIC_LVTT;
	const char *reg_str = "APIC_LVTT";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val &= ~APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U,
		msg, "clear APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U, msg, reg_str);
}

/*    <9: 146052 - 27536> Local APIC_mask bit in LVT when Software re-enabling_009 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27536_mask_bit_in_lvt_when_software_re_enabling_009(void)
{
        const char *msg =
		"local_apic_rqmid_27536_mask_bit_in_lvt_when_software_re_enabling_009";
	const unsigned reg = APIC_LVTCMCI;
	const char *reg_str = "APIC_LVTCMCI";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val &= ~APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U,
		msg, "clear APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U, msg, reg_str);
}

/*    <10: 146052 - 27535> Local APIC_mask bit in LVT when Software re-enabling_010 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27535_mask_bit_in_lvt_when_software_re_enabling_010(void)
{
        const char *msg =
		"local_apic_rqmid_27535_mask_bit_in_lvt_when_software_re_enabling_010";
	const unsigned reg = APIC_LVTTHMR;
	const char *reg_str = "APIC_LVTTHMR";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val &= ~APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U,
		msg, "clear APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U, msg, reg_str);
}

/*    <11: 146052 - 27532> Local APIC_mask bit in LVT when Software re-enabling_011 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27532_mask_bit_in_lvt_when_software_re_enabling_011(void)
{
        const char *msg =
		"local_apic_rqmid_27532_mask_bit_in_lvt_when_software_re_enabling_011";
	const unsigned reg = APIC_LVTPC;
	const char *reg_str = "APIC_LVTPC";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val &= ~APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U,
		msg, "clear APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U, msg, reg_str);
}

/*    <12: 146052 - 27529> Local APIC_mask bit in LVT when Software re-enabling_012 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27529_mask_bit_in_lvt_when_software_re_enabling_012(void)
{
        const char *msg =
		"local_apic_rqmid_27529_mask_bit_in_lvt_when_software_re_enabling_012";
	const unsigned reg = APIC_LVT0;
	const char *reg_str = "APIC_LVT0";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val &= ~APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U,
		msg, "clear APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U, msg, reg_str);
}

/*    <13: 146052 - 27525> Local APIC_mask bit in LVT when Software re-enabling_013 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27525_mask_bit_in_lvt_when_software_re_enabling_013(void)
{
        const char *msg =
		"local_apic_rqmid_27525_mask_bit_in_lvt_when_software_re_enabling_013";
	const unsigned reg = APIC_LVT1;
	const char *reg_str = "APIC_LVT1";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val &= ~APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U,
		msg, "clear APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U, msg, reg_str);
}

/*    <14: 146052 - 27522> Local APIC_mask bit in LVT when Software re-enabling_014 */

/**
 * @brief case name mask bit in LVT when Software re-enabling
 *
 * Summary: When a vCPU writes LAPIC SVR, the old guest LAPIC SVR[bit 8] is 1 and the new
 *  guest LAPIC SVR[bit 8] is 0, ACRN hypervisor shall guarantee that guest LAPIC LVT
 *  [bit 16] is unchanged.
 *  Bit 16 (i.e. the masking bit) of all LVT entries are set when SVR [bit 8] is set
 *  to 1 and kept unchangeable afterwards until SVR [bit 8] is set back to 0. But
 *  local interrupts are not re-enabled by clearing SVR [bit 8] alone. They shall
 *  keep masked until the software re-enables them. This is the native behavior but
 *  not explicitly stated in SDM. Thus record this as a separate requirement.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27522_mask_bit_in_lvt_when_software_re_enabling_014(void)
{
        const char *msg =
		"local_apic_rqmid_27522_mask_bit_in_lvt_when_software_re_enabling_014";
	const unsigned reg = APIC_LVTERR;
	const char *reg_str = "APIC_LVTERR";
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	val = apic_read(APIC_SPIV);
	report("%s - %s", (val & APIC_SPIV_APIC_ENABLED) == APIC_SPIV_APIC_ENABLED,
		msg, "Enable the APIC by set APIC_SPIV_APIC_ENABLED");
	if (!(val & APIC_SPIV_APIC_ENABLED))
		return;

	val = apic_read(reg);
	val &= ~APIC_LVT_MASKED;
	apic_write(reg, val);

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U,
		msg, "clear APIC_LVT_MASKED");

        val = apic_read(APIC_SPIV);
        val &= ~APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);
	mb();

	val = apic_read(reg);
	report("%s - %s", (val & APIC_LVT_MASKED) == 0U, msg, reg_str);
}

/* Summary: 14 Case for Requirement: 146053 delivery status bit of LVT */
/*    <1: 146053 - 27520> Local APIC_delivery status bit of LVT_001 */

static atomic_t lapic_delivery_status_isr_count;
static void lapic_delivery_status_isr(isr_regs_t *regs)
{
        (void) regs;
        atomic_inc(&lapic_delivery_status_isr_count);

        eoi();
}

static void lapic_set_delivery_status(void *addr)
{
        unsigned long reg = (unsigned long)addr;
        unsigned val = apic_read(reg);
        apic_write(reg, val | APIC_SEND_PENDING);
}

static void lapic_clear_delivery_status(void *addr)
{
        unsigned long reg = (unsigned long)addr;
        unsigned val = apic_read(reg);
        apic_write(reg, val & (~APIC_SEND_PENDING));
}

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27520_delivery_status_bit_of_lvt_001(void)
{
        static const char *msg =
                "local_apic_rqmid_27544_mask_bit_in_lvt_when_software_re_enabling_001";
        static const unsigned vec = LAPIC_TEST_VEC;
        static const unsigned long reg = APIC_LVTT;
        static const char *reg_str = "APIC_LVTT";
        static unsigned val;
        static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


        irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

        err = test_for_exception(GP_VECTOR, lapic_set_delivery_status, (void *)reg);
        report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
                msg, reg_str);
}


/*    <2: 146053 - 27517> Local APIC_delivery status bit of LVT_002 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27517_delivery_status_bit_of_lvt_002(void)
{
        static const char *msg =
                "local_apic_rqmid_27517_delivery_status_bit_of_lvt_002";
        static const unsigned vec = LAPIC_TEST_VEC;
        static const unsigned long reg = APIC_LVTT;
        static const char *reg_str = "APIC_LVTT";
        static unsigned val;
        static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


        irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

        err = test_for_exception(GP_VECTOR, lapic_clear_delivery_status, (void *)reg);
        report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
                msg, reg_str);
}

/*    <3: 146053 - 27514> Local APIC_delivery status bit of LVT_003 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27514_delivery_status_bit_of_lvt_003(void)
{
        static const char *msg =
		"local_apic_rqmid_27514_delivery_status_bit_of_lvt_003";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVTCMCI;
	static const char *reg_str = "APIC_LVTCMCI";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_set_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <4: 146053 - 27511> Local APIC_delivery status bit of LVT_004 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27511_delivery_status_bit_of_lvt_004(void)
{
        static const char *msg =
		"local_apic_rqmid_27511_delivery_status_bit_of_lvt_004";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVTCMCI;
	static const char *reg_str = "APIC_LVTCMCI";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_clear_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <5: 146053 - 27508> Local APIC_delivery status bit of LVT_005 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27508_delivery_status_bit_of_lvt_005(void)
{
        static const char *msg =
		"local_apic_rqmid_27508_delivery_status_bit_of_lvt_005";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVTTHMR;
	static const char *reg_str = "APIC_LVTTHMR";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_set_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <6: 146053 - 27504> Local APIC_delivery status bit of LVT_006 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27504_delivery_status_bit_of_lvt_006(void)
{
        static const char *msg =
		"local_apic_rqmid_27504_delivery_status_bit_of_lvt_006";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVTTHMR;
	static const char *reg_str = "APIC_LVTTHMR";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_clear_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <7: 146053 - 27501> Local APIC_delivery status bit of LVT_007 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27501_delivery_status_bit_of_lvt_007(void)
{
        static const char *msg =
		"local_apic_rqmid_27501_delivery_status_bit_of_lvt_007";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVTPC;
	static const char *reg_str = "APIC_LVTPC";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_set_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <8: 146053 - 27498> Local APIC_delivery status bit of LVT_008 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27498_delivery_status_bit_of_lvt_008(void)
{
        static const char *msg =
		"local_apic_rqmid_27498_delivery_status_bit_of_lvt_008";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVTPC;
	static const char *reg_str = "APIC_LVTPC";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_clear_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <9: 146053 - 27494> Local APIC_delivery status bit of LVT_009 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27494_delivery_status_bit_of_lvt_009(void)
{
        static const char *msg =
		"local_apic_rqmid_27494_delivery_status_bit_of_lvt_009";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVT0;
	static const char *reg_str = "APIC_LVT0";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_set_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <10: 146053 - 27730> Local APIC_delivery status bit of LVT_010 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27730_delivery_status_bit_of_lvt_010(void)
{
        static const char *msg =
		"local_apic_rqmid_27730_delivery_status_bit_of_lvt_010";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVT0;
	static const char *reg_str = "APIC_LVT0";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_clear_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <11: 146053 - 27727> Local APIC_delivery status bit of LVT_011 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27727_delivery_status_bit_of_lvt_011(void)
{
        static const char *msg =
		"local_apic_rqmid_27727_delivery_status_bit_of_lvt_011";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVT1;
	static const char *reg_str = "APIC_LVT1";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_set_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <12: 146053 - 27729> Local APIC_delivery status bit of LVT_012 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27729_delivery_status_bit_of_lvt_012(void)
{
        static const char *msg =
		"local_apic_rqmid_27729_delivery_status_bit_of_lvt_012";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVT1;
	static const char *reg_str = "APIC_LVT1";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_clear_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <13: 146053 - 27726> Local APIC_delivery status bit of LVT_013 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27726_delivery_status_bit_of_lvt_013(void)
{
        static const char *msg =
		"local_apic_rqmid_27726_delivery_status_bit_of_lvt_013";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVTERR;
	static const char *reg_str = "APIC_LVTERR";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_set_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/*    <14: 146053 - 27728> Local APIC_delivery status bit of LVT_014 */

/**
 * @brief case name delivery status bit of LVT
 *
 * Summary: When a vCPU attempts to write LAPIC LVT [bit 12], ACRN hypervisor shall ignore
 *  the write to this bit.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27728_delivery_status_bit_of_lvt_014(void)
{
        static const char *msg =
		"local_apic_rqmid_27728_delivery_status_bit_of_lvt_014";
	static const unsigned vec = LAPIC_TEST_VEC;
	static const unsigned long reg = APIC_LVTERR;
	static const char *reg_str = "APIC_LVTERR";
        static unsigned val;
	static int err;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);


	irq_disable();
        atomic_set(&lapic_delivery_status_isr_count, 0);
        handle_irq(vec, lapic_delivery_status_isr);
        irq_enable();

	err = test_for_exception(GP_VECTOR, lapic_clear_delivery_status, (void *)reg);
	report("%s - %s", (err == 0) && atomic_read(&lapic_delivery_status_isr_count) == 0,
		msg, reg_str);
}

/* Summary: 2 Case for Requirement: 146054 Set Initial Counter Register, Current Count Register and IA32_TSCDEADLINE to 0H after setting time mode to be 3H */
/*    <1: 146054 - 27725> Local APIC_Set Initial Counter Register, Current Count Register and IA32_TSCDEADLINE to 0H after setting time mode to be 3H_001 */

/**
 * @brief case name Set Initial Counter Register, Current Count Register and IA32_TSCDEADLINE to 0H after setting time mode to be 3H
 *
 * Summary: When a vCPU writes LAPIC timer register and the new guest LAPIC timer register
 *  [bit 18:17] is 3H, ACRN hypervisor shall set guest LAPIC initial count register,
 *  guest LAPIC current count register and guest IA32TSCDEADLINE to 0H.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27725_set_initial_counter_register_current_count_register_and_ia32_tscdeadline_to_0h_after_setting_time_mode_to_be_3h_001(void)
{
	const char *msg = "local_apic_rqmid_27725_"
		"set_initial_counter_register_current_count_register_and_"
		"ia32_tscdeadline_to_0h_after_setting_time_mode_to_be_3h_0";
	unsigned long val;
	unsigned vec = LAPIC_TEST_VEC;
        val = apic_read(APIC_LVTT);
        val &= ~APIC_VECTOR_MASK;
        val |= vec;
        val |= APIC_LVT_MASKED;

        val |= APIC_LVT_TIMER_MASK;

        val &= LAPIC_REG_MASK;
        apic_write(APIC_LVTT, val);
        mb();

	val = apic_read(APIC_TMICT);
	report("%s - %s", val == 0UL, msg, "APIC_TMICT");
	val = apic_read(APIC_TMCCT);
	report("%s - %s", val == 0UL, msg, "APIC_TMCCT");
	val = rdmsr(MSR_IA32_TSCDEADLINE);
	report("%s - %s", val == 0UL, msg, "IA32_TSCDEADLINE");
}

/*    <2: 146054 - 27724> Local APIC_Set Initial Counter Register, Current Count Register and IA32_TSCDEADLINE to 0H after setting time mode to be 3H_002 */

/**
 * @brief case name Set Initial Counter Register, Current Count Register and IA32_TSCDEADLINE to 0H after setting time mode to be 3H
 *
 * Summary: When a vCPU writes LAPIC timer register and the new guest LAPIC timer register
 *  [bit 18:17] is 3H, ACRN hypervisor shall set guest LAPIC initial count register,
 *  guest LAPIC current count register and guest IA32TSCDEADLINE to 0H.
 *  Keep the behavior the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27724_set_initial_counter_register_current_count_register_and_ia32_tscdeadline_to_0h_after_setting_time_mode_to_be_3h_002(void)
{
	const char *msg = __func__;
	unsigned long val;
	unsigned vec = LAPIC_TEST_VEC;

	unsigned long apic_base_status = rdmsr(MSR_IA32_APICBASE);
	if (apic_base_status & APIC_EXTD)
		return;

        val = apic_read(APIC_LVTT);
        val &= ~APIC_VECTOR_MASK;
        val |= vec;
        val |= APIC_LVT_MASKED;

        val |= APIC_LVT_TIMER_MASK;

        val &= LAPIC_REG_MASK;
        apic_write(APIC_LVTT, val);
        mb();

	val = apic_read(APIC_TMICT);
	report("%s - %s", val == 0UL, msg, "APIC_TMICT");
	val = apic_read(APIC_TMCCT);
	report("%s - %s", val == 0UL, msg, "APIC_TMCCT");
	val = rdmsr(MSR_IA32_TSCDEADLINE);
	report("%s - %s", val == 0UL, msg, "IA32_TSCDEADLINE");
}

/* Summary: 2 Case for Requirement: 146055 value of Initial Count Register when LVT timer bit 18 is 1 */
/*    <1: 146055 - 27723> Local APIC_value of Initial Count Register when LVT timer bit 18 is 1_001 */

/**
 * @brief case name value of Initial Count Register when LVT timer bit 18 is 1
 *
 * Summary: When a vCPU reads LAPIC initial count register and guest LVT timer register [bit
 *  18] is 1, ACRN hypervisor shall guarantee that the vCPU gets 0H.
 *  Initial count register is useless when the LAPIC timer is in TSC deadline mode
 *  or the reserved mode. The value from this register in such cases are not
 *  explicitly stated in SDM. Thus state the value in a separate requirement and keep
 *  the value consistent with LAPIC current count register.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27723_value_of_initial_count_register_when_lvt_timer_bit_18_is_1_001(void)
{
	const char *msg =
		"local_apic_rqmid_27723_value_of_initial_count_register_when_lvt_timer_bit_18_is_1_001";
	unsigned long val;
	unsigned vec = LAPIC_TEST_VEC;
        val = apic_read(APIC_LVTT);
        val &= ~APIC_VECTOR_MASK;
        val |= vec;
        val |= APIC_LVT_MASKED;

        val |= APIC_LVT_TIMER_MASK;

        val &= LAPIC_REG_MASK;
        apic_write(APIC_LVTT, val);
        mb();

	val = apic_read(APIC_TMICT);
	report("%s - %s", val == 0UL, msg, "APIC_TMICT");
}

/*    <2: 146055 - 27721> Local APIC_value of Initial Count Register when LVT timer bit 18 is 1_002 */

/**
 * @brief case name value of Initial Count Register when LVT timer bit 18 is 1
 *
 * Summary: When a vCPU reads LAPIC initial count register and guest LVT timer register [bit
 *  18] is 1, ACRN hypervisor shall guarantee that the vCPU gets 0H.
 *  Initial count register is useless when the LAPIC timer is in TSC deadline mode
 *  or the reserved mode. The value from this register in such cases are not
 *  explicitly stated in SDM. Thus state the value in a separate requirement and keep
 *  the value consistent with LAPIC current count register.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27721_value_of_initial_count_register_when_lvt_timer_bit_18_is_1_002(void)
{
	const char *msg =
		"local_apic_rqmid_27721_value_of_initial_count_register_when_lvt_timer_bit_18_is_1_002";
	unsigned long val;
	unsigned vec = LAPIC_TEST_VEC;
        val = apic_read(APIC_LVTT);
        val &= ~APIC_VECTOR_MASK;
        val |= vec;
        val |= APIC_LVT_MASKED;

        val &= ~APIC_LVT_TIMER_MASK;
	val |= APIC_LVT_TIMER_TSCDEADLINE;

        val &= LAPIC_REG_MASK;
        apic_write(APIC_LVTT, val);
        mb();

	val = apic_read(APIC_TMICT);
	report("%s - %s", val == 0UL, msg, "APIC_TMICT");
}

/* Summary: 4 Case for Requirement: 146057 Safety VM must program fixed or NMI delivery mode to its CMCI LVT. */
/*    <1: 146057 - 27720> Local APIC_Safety VM must program fixed or NMI delivery mode to its CMCI LVT._001 */

/**
 * @brief case name Safety VM must program fixed or NMI delivery mode to its CMCI LVT.
 *
 * Summary: The safety VM shall program the delivery mode of LVT CMCI register to either
 *  fixed or NMI.
 *  The safety VM can program LVT CMCI as well as trigger CMCI by configuring MSRs
 *  of machine check architecture (MCA). INIT and ExtINT are unsupported delivery
 *  mode for CMCI, but SDM does not state the behavior if either of them are
 *  programmed and a CMCI is triggered. CMCI shall not be delivered as SMI, either,
 *  because how it will be handled is unspecified.
 *  This is not applicable to the non-safety VM because MCA is hidden from it and it
 *  has no way to trigger CMCI.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27720_safety_vm_must_program_fixed_or_nmi_delivery_mode_to_its_cmci_lvt_001(void)
{
	const char *msg = LAPIC_SAFETY_STRING
		"local_apic_rqmid_27720_safety_vm_must_program_fixed_or_nmi_delivery_mode_to_its_cmci_lvt_001";
	unsigned long val;

	if(!lapic_is_in_safety_mode())
		return;
        val = apic_read(APIC_LVTCMCI);
        val &= APIC_MODE_MASK;
	report("%s", (val == APIC_DM_FIXED) || (val == APIC_DM_NMI), msg);
}

/*    <2: 146057 - 27718> Local APIC_Safety VM must program fixed or NMI delivery mode to its CMCI LVT._002 */

/**
 * @brief case name Safety VM must program fixed or NMI delivery mode to its CMCI LVT.
 *
 * Summary: The safety VM shall program the delivery mode of LVT CMCI register to either
 *  fixed or NMI.
 *  The safety VM can program LVT CMCI as well as trigger CMCI by configuring MSRs
 *  of machine check architecture (MCA). INIT and ExtINT are unsupported delivery
 *  mode for CMCI, but SDM does not state the behavior if either of them are
 *  programmed and a CMCI is triggered. CMCI shall not be delivered as SMI, either,
 *  because how it will be handled is unspecified.
 *  This is not applicable to the non-safety VM because MCA is hidden from it and it
 *  has no way to trigger CMCI.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27718_safety_vm_must_program_fixed_or_nmi_delivery_mode_to_its_cmci_lvt_002(void)
{
	/* non-safety? */
	const char *msg = __func__;

	if(lapic_is_in_safety_mode())
		return;
        val = apic_read(APIC_LVTCMCI);
        val &= APIC_MODE_MASK;
	report("%s", (val == APIC_DM_FIXED) || (val == APIC_DM_NMI), msg);
}

/*    <3: 146057 - 27719> Local APIC_Safety VM must program fixed or NMI delivery mode to its CMCI LVT._003 */

/**
 * @brief case name Safety VM must program fixed or NMI delivery mode to its CMCI LVT.
 *
 * Summary: The safety VM shall program the delivery mode of LVT CMCI register to either
 *  fixed or NMI.
 *  The safety VM can program LVT CMCI as well as trigger CMCI by configuring MSRs
 *  of machine check architecture (MCA). INIT and ExtINT are unsupported delivery
 *  mode for CMCI, but SDM does not state the behavior if either of them are
 *  programmed and a CMCI is triggered. CMCI shall not be delivered as SMI, either,
 *  because how it will be handled is unspecified.
 *  This is not applicable to the non-safety VM because MCA is hidden from it and it
 *  has no way to trigger CMCI.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27719_safety_vm_must_program_fixed_or_nmi_delivery_mode_to_its_cmci_lvt_003(void)
{
	const char *msg = "local_apic_rqmid_27719_safety_vm_must_program_fixed_or_nmi_delivery_mode_to_its_cmci_lvt_003";
	report("deprecated: %s", 0, msg);
}

/*    <4: 146057 - 27717> Local APIC_Safety VM must program fixed or NMI delivery mode to its CMCI LVT._004 */

/**
 * @brief case name Safety VM must program fixed or NMI delivery mode to its CMCI LVT.
 *
 * Summary: The safety VM shall program the delivery mode of LVT CMCI register to either
 *  fixed or NMI.
 *  The safety VM can program LVT CMCI as well as trigger CMCI by configuring MSRs
 *  of machine check architecture (MCA). INIT and ExtINT are unsupported delivery
 *  mode for CMCI, but SDM does not state the behavior if either of them are
 *  programmed and a CMCI is triggered. CMCI shall not be delivered as SMI, either,
 *  because how it will be handled is unspecified.
 *  This is not applicable to the non-safety VM because MCA is hidden from it and it
 *  has no way to trigger CMCI.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27717_safety_vm_must_program_fixed_or_nmi_delivery_mode_to_its_cmci_lvt_004(void)
{
	const char *msg = "local_apic_rqmid_27717_safety_vm_must_program_fixed_or_nmi_delivery_mode_to_its_cmci_lvt";
	report("deprecated: %s", 0, msg);
}

/* Summary: 2 Case for Requirement: 146065 ignore ICR write of level bit */
/*    <1: 146065 - 27716> Local APIC_ignore ICR write of level bit_001 */

/**
 * @brief case name ignore ICR write of level bit
 *
 * Summary: When a vCPU attempts to write ICR[bit 14], ACRN hypervisor shall guarantee that
 *  the write to the bit is ignored.
 *  This flag has no meaning in Pentium 4 and Intel Xeon processors and will always
 *  be issued as a 1. Write this bit on native will be ignored. Keep the behavior the
 *  same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27716_ignore_icr_write_of_level_bit_001(void)
{
        const char *msg = "local_apic_rqmid_27716_ignore_icr_write_of_level_bit_001";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
	unsigned long icr;
	unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 1) &&
		((icr & APIC_INT_ASSERT) == 0UL), msg);
}

/*    <2: 146065 - 27715> Local APIC_ignore ICR write of level bit_002 */

/**
 * @brief case name ignore ICR write of level bit
 *
 * Summary: When a vCPU attempts to write ICR[bit 14], ACRN hypervisor shall guarantee that
 *  the write to the bit is ignored.
 *  This flag has no meaning in Pentium 4 and Intel Xeon processors and will always
 *  be issued as a 1. Write this bit on native will be ignored. Keep the behavior the
 *  same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27715_ignore_icr_write_of_level_bit_002(void)
{
        const char *msg = "local_apic_rqmid_27715_ignore_icr_write_of_level_bit_002";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED | APIC_INT_ASSERT;
	unsigned long icr;
	unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

	icr = apic_read(APIC_ICR);
        report("%s", (atomic_read(&lapic_ipi_isr_count) == 1) &&
		((icr & APIC_INT_ASSERT) == 0UL), msg);
}

/* Summary: 2 Case for Requirement: 146066 ignore ICR write of trigger mode bit */
/*    <1: 146066 - 27714> Local APIC_ignore ICR write of trigger mode bit_001 */

/**
 * @brief case name ignore ICR write of trigger mode bit
 *
 * Summary: When a vCPU attempts to write ICR[bit 15], ACRN hypervisor shall guarantee that
 *  the write to the bit is ignored.
 *  This flag has no meaning in Pentium 4 and Intel Xeon processors, and will always
 *  be issued as a 0. Write this bit on native will be ignored. Keep the behavior
 *  the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27714_ignore_icr_write_of_trigger_mode_bit_001(void)
{
        const char *msg = "local_apic_rqmid_27714_ignore_icr_write_of_trigger_mode_bit_001";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED | APIC_INT_ASSERT;
	unsigned long icr;
	unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

	icr = apic_read(APIC_ICR);
        report("%s", (atomic_read(&lapic_ipi_isr_count) == 1) &&
		((icr & APIC_INT_LEVELTRIG) == 0UL), msg);
}

/*    <2: 146066 - 27713> Local APIC_ignore ICR write of trigger mode bit_002 */

/**
 * @brief case name ignore ICR write of trigger mode bit
 *
 * Summary: When a vCPU attempts to write ICR[bit 15], ACRN hypervisor shall guarantee that
 *  the write to the bit is ignored.
 *  This flag has no meaning in Pentium 4 and Intel Xeon processors, and will always
 *  be issued as a 0. Write this bit on native will be ignored. Keep the behavior
 *  the same with the native.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27713_ignore_icr_write_of_trigger_mode_bit_002(void)
{
        const char *msg = "local_apic_rqmid_27713_ignore_icr_write_of_trigger_mode_bit_002";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED | APIC_INT_LEVELTRIG;
	unsigned long icr;
	unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

	icr = apic_read(APIC_ICR);

	/* on physical ignored bit - so It Still should get the #INTR */
        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) &&
		((icr & APIC_INT_LEVELTRIG) == 0UL), msg);
}

/* Summary: 32 Case for Requirement: 146067 Interrupt Delivery with illegal vector */
/*    <1: 146067 - 27712> Local APIC_Interrupt Delivery with illegal vector_001 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27712_interrupt_delivery_with_illegal_vector_001(void)
{
        const char *msg = "local_apic_rqmid_27712_interrupt_delivery_with_illegal_vector_001";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_INVALID_VEC;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}


/*    <2: 146067 - 27711> Local APIC_Interrupt Delivery with illegal vector_002 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27711_interrupt_delivery_with_illegal_vector_002(void)
{
        const char *msg = "local_apic_rqmid_27711_interrupt_delivery_with_illegal_vector_002";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 1U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <3: 146067 - 27710> Local APIC_Interrupt Delivery with illegal vector_003 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27710_interrupt_delivery_with_illegal_vector_003(void)
{
        const char *msg = "local_apic_rqmid_27710_interrupt_delivery_with_illegal_vector_003";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 2U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <4: 146067 - 27708> Local APIC_Interrupt Delivery with illegal vector_004 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27708_interrupt_delivery_with_illegal_vector_004(void)
{
        const char *msg = "local_apic_rqmid_27708_interrupt_delivery_with_illegal_vector_004";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 3U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <5: 146067 - 27707> Local APIC_Interrupt Delivery with illegal vector_005 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27707_interrupt_delivery_with_illegal_vector_005(void)
{
        const char *msg = "local_apic_rqmid_27707_interrupt_delivery_with_illegal_vector_005";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 4U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <6: 146067 - 27706> Local APIC_Interrupt Delivery with illegal vector_006 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27706_interrupt_delivery_with_illegal_vector_006(void)
{
        const char *msg = "local_apic_rqmid_27706_interrupt_delivery_with_illegal_vector_006";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 5U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <7: 146067 - 27705> Local APIC_Interrupt Delivery with illegal vector_007 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27705_interrupt_delivery_with_illegal_vector_007(void)
{
        const char *msg = "local_apic_rqmid_27705_interrupt_delivery_with_illegal_vector_007";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 6U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <8: 146067 - 27703> Local APIC_Interrupt Delivery with illegal vector_008 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27703_interrupt_delivery_with_illegal_vector_008(void)
{
        const char *msg = "local_apic_rqmid_27703_interrupt_delivery_with_illegal_vector_008";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 7U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <9: 146067 - 27704> Local APIC_Interrupt Delivery with illegal vector_009 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27704_interrupt_delivery_with_illegal_vector_009(void)
{
        const char *msg = "local_apic_rqmid_27704_interrupt_delivery_with_illegal_vector_009";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 8U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <10: 146067 - 27702> Local APIC_Interrupt Delivery with illegal vector_010 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27702_interrupt_delivery_with_illegal_vector_010(void)
{
        const char *msg = "local_apic_rqmid_27702_interrupt_delivery_with_illegal_vector_010";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 9U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <11: 146067 - 27528> Local APIC_Interrupt Delivery with illegal vector_011 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27528_interrupt_delivery_with_illegal_vector_011(void)
{
        const char *msg = "local_apic_rqmid_27528_interrupt_delivery_with_illegal_vector_011";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 10U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <12: 146067 - 27524> Local APIC_Interrupt Delivery with illegal vector_012 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27524_interrupt_delivery_with_illegal_vector_012(void)
{
        const char *msg = "local_apic_rqmid_27524_interrupt_delivery_with_illegal_vector_012";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 11U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <13: 146067 - 27519> Local APIC_Interrupt Delivery with illegal vector_013 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27519_interrupt_delivery_with_illegal_vector_013(void)
{
        const char *msg = "local_apic_rqmid_27519_interrupt_delivery_with_illegal_vector_013";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 12U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <14: 146067 - 27516> Local APIC_Interrupt Delivery with illegal vector_014 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27516_interrupt_delivery_with_illegal_vector_014(void)
{
        const char *msg = "local_apic_rqmid_27516_interrupt_delivery_with_illegal_vector_014";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 13U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <15: 146067 - 27701> Local APIC_Interrupt Delivery with illegal vector_015 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27701_interrupt_delivery_with_illegal_vector_015(void)
{
        const char *msg = "local_apic_rqmid_27701_interrupt_delivery_with_illegal_vector_015";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 14U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <16: 146067 - 27513> Local APIC_Interrupt Delivery with illegal vector_016 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27513_interrupt_delivery_with_illegal_vector_016(void)
{
        const char *msg = "local_apic_rqmid_27513_interrupt_delivery_with_illegal_vector_016";

        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = 15U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <17: 146067 - 27510> Local APIC_Interrupt Delivery with illegal vector_017 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27510_interrupt_delivery_with_illegal_vector_017(void)
{
        const char *msg = "local_apic_rqmid_27510_interrupt_delivery_with_illegal_vector_017";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = LAPIC_TEST_INVALID_VEC;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <18: 146067 - 27506> Local APIC_Interrupt Delivery with illegal vector_018 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27506_interrupt_delivery_with_illegal_vector_018(void)
{
        const char *msg = "local_apic_rqmid_27506_interrupt_delivery_with_illegal_vector_018";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 1U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <19: 146067 - 27503> Local APIC_Interrupt Delivery with illegal vector_019 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27503_interrupt_delivery_with_illegal_vector_019(void)
{
        const char *msg = "local_apic_rqmid_27503_interrupt_delivery_with_illegal_vector_019";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 2U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <20: 146067 - 27500> Local APIC_Interrupt Delivery with illegal vector_020 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27500_interrupt_delivery_with_illegal_vector_020(void)
{
        const char *msg = "local_apic_rqmid_27500_interrupt_delivery_with_illegal_vector_020";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 3U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <21: 146067 - 27496> Local APIC_Interrupt Delivery with illegal vector_021 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27496_interrupt_delivery_with_illegal_vector_021(void)
{
        const char *msg = "local_apic_rqmid_27496_interrupt_delivery_with_illegal_vector_021";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 4U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <22: 146067 - 27530> Local APIC_Interrupt Delivery with illegal vector_022 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27530_interrupt_delivery_with_illegal_vector_022(void)
{
        const char *msg = "local_apic_rqmid_27530_interrupt_delivery_with_illegal_vector_022";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 5U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <23: 146067 - 27526> Local APIC_Interrupt Delivery with illegal vector_023 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27526_interrupt_delivery_with_illegal_vector_023(void)
{
        const char *msg = "local_apic_rqmid_27526_interrupt_delivery_with_illegal_vector_023";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 6U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <24: 146067 - 27523> Local APIC_Interrupt Delivery with illegal vector_024 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27523_interrupt_delivery_with_illegal_vector_024(void)
{
        const char *msg = "local_apic_rqmid_27523_interrupt_delivery_with_illegal_vector_024";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 7U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <25: 146067 - 27521> Local APIC_Interrupt Delivery with illegal vector_025 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27521_interrupt_delivery_with_illegal_vector_025(void)
{
        const char *msg = "local_apic_rqmid_27521_interrupt_delivery_with_illegal_vector_025";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 8U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <26: 146067 - 27518> Local APIC_Interrupt Delivery with illegal vector_026 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27518_interrupt_delivery_with_illegal_vector_026(void)
{
        const char *msg = "local_apic_rqmid_27518_interrupt_delivery_with_illegal_vector_026";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 9U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <27: 146067 - 27515> Local APIC_Interrupt Delivery with illegal vector_027 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27515_interrupt_delivery_with_illegal_vector_027(void)
{
        const char *msg = "local_apic_rqmid_27515_interrupt_delivery_with_illegal_vector_027";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 10U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <28: 146067 - 27512> Local APIC_Interrupt Delivery with illegal vector_028 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27512_interrupt_delivery_with_illegal_vector_028(void)
{
        const char *msg = "local_apic_rqmid_27512_interrupt_delivery_with_illegal_vector_028";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 11U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <29: 146067 - 27509> Local APIC_Interrupt Delivery with illegal vector_029 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27509_interrupt_delivery_with_illegal_vector_029(void)
{
        const char *msg = "local_apic_rqmid_27509_interrupt_delivery_with_illegal_vector_029";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 12U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <30: 146067 - 27505> Local APIC_Interrupt Delivery with illegal vector_030 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27505_interrupt_delivery_with_illegal_vector_030(void)
{
        const char *msg = "local_apic_rqmid_27505_interrupt_delivery_with_illegal_vector_030";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 13U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <31: 146067 - 27502> Local APIC_Interrupt Delivery with illegal vector_031 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27502_interrupt_delivery_with_illegal_vector_031(void)
{
        const char *msg = "local_apic_rqmid_27502_interrupt_delivery_with_illegal_vector_031";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 14U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/*    <32: 146067 - 27499> Local APIC_Interrupt Delivery with illegal vector_032 */

/**
 * @brief case name Interrupt Delivery with illegal vector
 *
 * Summary: When a fixed interrupt is triggered and the vector is less than 10H, ACRN
 *  hypervisor shall guarantee that the interrupt is ignored.
 *  Interrupt Delivery with illegal vector shall never been issued.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27499_interrupt_delivery_with_illegal_vector_032(void)
{
        const char *msg = "local_apic_rqmid_27499_interrupt_delivery_with_illegal_vector_032";

        const unsigned int destination = LAPIC_INTR_TARGET_ID1;
        const unsigned int vec = 15U;
        const unsigned int mode = APIC_DEST_PHYSICAL | APIC_DM_FIXED;
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr != 0U), msg);
}

/* Summary: 4 Case for Requirement: 146068 x2APIC IPI with unsupported delivery mode  */
/*    <1: 146068 - 27495> Local APIC_x2APIC IPI with unsupported delivery mode_001 */

/**
 * @brief case name x2APIC IPI with unsupported delivery mode
 *
 * Summary: When a vCPU writes LAPIC ICR, ACRN hypervisor shall guarantee that the IPI issue
 *  request is ignored if any of the following conditions is met.

 *  The new guest LAPIC ICR [bit 10:8] is 1H.

 *  The new guest LAPIC ICR [bit 10:8] is 2H.

 *  The new guest LAPIC ICR [bit 10:8] is 3H.

 *  The new guest LAPIC ICR [bit 10:8] is 7H.
 *  Issuing a lowest priority IPI should be avoided by the operating system software
 *  according to Chapter 10.6.1, Vol. 3, SDM. Such request shall be ignored for
 *  deterministic behavior.
 *  Issuing an SMI (delivery mode being 2H) by IPI is not intended due to the
 *  non-deterministic behavior of SMI handling. Such IPI issue request shall be
 *  ignored.
 *  Issuing an IPI with a reserved delivery mode (3H or 7H) shall not trigger any
 *  IPI.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27495_x2apic_ipi_with_unsupported_delivery_mode_001(void)
{
        const char *msg = "local_apic_rqmid_27495_x2apic_ipi_with_unsupported_delivery_mode_001";
        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = SET_APIC_DELIVERY_MODE(APIC_DEST_PHYSICAL, APIC_DM_LOWEST);
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr == 0U), msg);
}

/*    <2: 146068 - 27700> Local APIC_x2APIC IPI with unsupported delivery mode_002 */

/**
 * @brief case name x2APIC IPI with unsupported delivery mode
 *
 * Summary: When a vCPU writes LAPIC ICR, ACRN hypervisor shall guarantee that the IPI issue
 *  request is ignored if any of the following conditions is met.

 *  The new guest LAPIC ICR [bit 10:8] is 1H.

 *  The new guest LAPIC ICR [bit 10:8] is 2H.

 *  The new guest LAPIC ICR [bit 10:8] is 3H.

 *  The new guest LAPIC ICR [bit 10:8] is 7H.
 *  Issuing a lowest priority IPI should be avoided by the operating system software
 *  according to Chapter 10.6.1, Vol. 3, SDM. Such request shall be ignored for
 *  deterministic behavior.
 *  Issuing an SMI (delivery mode being 2H) by IPI is not intended due to the
 *  non-deterministic behavior of SMI handling. Such IPI issue request shall be
 *  ignored.
 *  Issuing an IPI with a reserved delivery mode (3H or 7H) shall not trigger any
 *  IPI.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27700_x2apic_ipi_with_unsupported_delivery_mode_002(void)
{
        const char *msg = "local_apic_rqmid_27700_x2apic_ipi_with_unsupported_delivery_mode_002";
        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = SET_APIC_DELIVERY_MODE(APIC_DEST_PHYSICAL, APIC_DM_SMI);
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr == 0U), msg);
}

/*    <3: 146068 - 27507> Local APIC_x2APIC IPI with unsupported delivery mode_003 */

/**
 * @brief case name x2APIC IPI with unsupported delivery mode
 *
 * Summary: When a vCPU writes LAPIC ICR, ACRN hypervisor shall guarantee that the IPI issue
 *  request is ignored if any of the following conditions is met.

 *  The new guest LAPIC ICR [bit 10:8] is 1H.

 *  The new guest LAPIC ICR [bit 10:8] is 2H.

 *  The new guest LAPIC ICR [bit 10:8] is 3H.

 *  The new guest LAPIC ICR [bit 10:8] is 7H.
 *  Issuing a lowest priority IPI should be avoided by the operating system software
 *  according to Chapter 10.6.1, Vol. 3, SDM. Such request shall be ignored for
 *  deterministic behavior.
 *  Issuing an SMI (delivery mode being 2H) by IPI is not intended due to the
 *  non-deterministic behavior of SMI handling. Such IPI issue request shall be
 *  ignored.
 *  Issuing an IPI with a reserved delivery mode (3H or 7H) shall not trigger any
 *  IPI.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27507_x2apic_ipi_with_unsupported_delivery_mode_003(void)
{
        const char *msg = "local_apic_rqmid_27507_x2apic_ipi_with_unsupported_delivery_mode_003";
        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = SET_APIC_DELIVERY_MODE(APIC_DEST_PHYSICAL, APIC_DM_REMRD);
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr == 0U), msg);
}

/*    <4: 146068 - 27534> Local APIC_x2APIC IPI with unsupported delivery mode_004 */

/**
 * @brief case name x2APIC IPI with unsupported delivery mode
 *
 * Summary: When a vCPU writes LAPIC ICR, ACRN hypervisor shall guarantee that the IPI issue
 *  request is ignored if any of the following conditions is met.

 *  The new guest LAPIC ICR [bit 10:8] is 1H.

 *  The new guest LAPIC ICR [bit 10:8] is 2H.

 *  The new guest LAPIC ICR [bit 10:8] is 3H.

 *  The new guest LAPIC ICR [bit 10:8] is 7H.
 *  Issuing a lowest priority IPI should be avoided by the operating system software
 *  according to Chapter 10.6.1, Vol. 3, SDM. Such request shall be ignored for
 *  deterministic behavior.
 *  Issuing an SMI (delivery mode being 2H) by IPI is not intended due to the
 *  non-deterministic behavior of SMI handling. Such IPI issue request shall be
 *  ignored.
 *  Issuing an IPI with a reserved delivery mode (3H or 7H) shall not trigger any
 *  IPI.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27534_x2apic_ipi_with_unsupported_delivery_mode_004(void)
{
        const char *msg = "local_apic_rqmid_27534_x2apic_ipi_with_unsupported_delivery_mode_004";
        const unsigned int destination = LAPIC_INTR_TARGET_SELF;
        const unsigned int vec = LAPIC_TEST_VEC;
        const unsigned int mode = SET_APIC_DELIVERY_MODE(APIC_DEST_PHYSICAL, APIC_DM_EXTINT);
        unsigned esr;
        unsigned val;

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        atomic_set(&lapic_ipi_isr_count, 0);

        irq_disable();
        handle_irq(vec, lapic_ipi_isr);
        irq_enable();

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        apic_icr_write(mode | vec, destination);

        mb();
        nop();
        lapic_busy_wait();

        esr = apic_read(APIC_ESR);

        report("%s", (atomic_read(&lapic_ipi_isr_count) == 0) && (esr == 0U), msg);
}

/* Summary: 2 Case for Requirement: 146072 ignore write of EOI when ISR is 0H */
/*    <1: 146072 - 27531> Local APIC_ignore write of EOI when ISR is 0H_001 */

/**
 * @brief case name ignore write of EOI when ISR is 0H
 *
 * Summary: When a vCPU attempts to write LAPIC EOI register and the guest LAPIC ISR is 0H,
 *  ACRN hypervisor shall guarantee that the write is ignored.
 *  No ISR bit be set, write to EOI is meaningless.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27531_ignore_write_of_eoi_when_isr_is_0h_001(void)
{
        const char *msg = "local_apic_rqmid_27531_ignore_write_of_eoi_when_isr_is_0h_001";
        const unsigned int vec = LAPIC_TEST_VEC;
        unsigned val;
        int ret1;
        int ret2;
        int cnt1;
        int cnt2;
        int i;

        irq_disable();
        for (i = LAPIC_FIRST_VEC; i < LAPIC_MAX_VEC; i += 1) {
                handle_irq(i, lapic_ipi_isr);
        }
        irq_enable();

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        ret1 = test_for_interrupt(vec, msg);
        cnt1 = atomic_read(&lapic_ipi_isr_count);
        while(1) {
                for(i = 0; i < APIC_ISR_NR; i += 1) {
                        val = apic_read(APIC_ISR + (i << 4));
                        if ( val != 0)
                                break;
                }
                if(i == APIC_ISR_NR)
                        break;
        }

        eoi();
        mb();

        ret2 = test_for_interrupt(vec, msg);
        cnt2 = atomic_read(&lapic_ipi_isr_count);
        report("%s", (ret1 != 0) && (cnt1 == 1) && (ret2 != 0) && (cnt2 == 1), msg);
}

/*    <2: 146072 - 27699> Local APIC_ignore write of EOI when ISR is 0H_002 */

/**
 * @brief case name ignore write of EOI when ISR is 0H
 *
 * Summary: When a vCPU attempts to write LAPIC EOI register and the guest LAPIC ISR is 0H,
 *  ACRN hypervisor shall guarantee that the write is ignored.
 *  No ISR bit be set, write to EOI is meaningless.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27699_ignore_write_of_eoi_when_isr_is_0h_002(void)
{
        static const char *msg = "local_apic_rqmid_27699_ignore_write_of_eoi_when_isr_is_0h_002";
        static const unsigned int vec = LAPIC_TEST_VEC;
        static unsigned val;
	static int err;
        static int ret1;
        static int ret2;
        static int cnt1;
        static int cnt2;
        static int i;

        irq_disable();
        for (i = LAPIC_FIRST_VEC; i < LAPIC_MAX_VEC; i += 1) {
                handle_irq(i, lapic_ipi_isr);
        }
        irq_enable();

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

        ret1 = test_for_interrupt(vec, msg);
        cnt1 = atomic_read(&lapic_ipi_isr_count);
        while(1) {
                for(i = 0; i < APIC_ISR_NR; i += 1) {
                        val = apic_read(APIC_ISR + (i << 4));
                        if ( val != 0)
                                break;
                }
                if(i == APIC_ISR_NR)
                        break;
        }

	err = test_for_exception(GP_VECTOR, lapic_write_eoi_non_zero, NULL);

        ret2 = test_for_interrupt(vec, msg);
        cnt2 = atomic_read(&lapic_ipi_isr_count);
        report("%s", (err != 0) && (ret1 != 0) && (cnt1 == 1) && (ret2 != 0) && (cnt2 == 1), msg);
}

/* Summary: 1 Case for Requirement: 146074 x2APIC LVT with SMI Delivery Mode  */
/*    <1: 146074 - 27934> Local APIC_x2APIC LVT with SMI Delivery Mode_001 */

/**
 * @brief case name x2APIC LVT with SMI Delivery Mode
 *
 * Summary: While a guest LAPIC LVT register [bit 9:8] is different from 0H, ACRN hypervisor
 *  shall guarantee that local interrupts controlled by the guest LVT register are
 *  ignored.
 *  Delivery mode with the 2 least significant bits being not 0H can be SMI, ExtINT,
 *  INIT or reserved. A VM is not supposed to trigger a SMI by local interrupts,
 *  considering the indeterministic behavior of SMI handling. Configuring an local
 *  interrupt to be ExtINT has no effect due to the lack of a legacy PIC or IOAPIC on
 *  the virtual platform. INIT is only valid for LINT0 for LINT1 which is not
 *  connected to any interrupt source. Thus configuring a local interrupt to be any
 *  of the delivery mode above shall essentially prevent the corresponding local
 *  interrupts from being delivered to the vCPU.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27934_x2apic_lvt_with_smi_delivery_mode_001(void)
{
	const char *msg = "local_apic_rqmid_27934_x2apic_lvt_with_smi_delivery_mode_001";
	unsigned long lvt[1] = {
		APIC_LVTT,
	};
	const unsigned vec = LAPIC_TEST_VEC;
	unsigned val;
	unsigned i;
	int err;

        irq_disable();
        for (i = LAPIC_FIRST_VEC; i < LAPIC_MAX_VEC; i += 1) {
                handle_irq(i, lapic_timer_isr);
        }
        irq_enable();

        val = apic_read(APIC_SPIV);
        val |= APIC_VECTOR_MASK;
        val |= APIC_SPIV_APIC_ENABLED;
        apic_write(APIC_SPIV, val);

	for (i = 0; i < sizeof(lvt)/sizeof(*lvt); i += 1) {

        if (apic_read(APIC_ESR) != 0U)
                apic_write(APIC_ESR, 0U);

	irq_disable();
	atomic_set(&lapic_timer_isr_count, 0);

	val = apic_read(lvt[i]);
	val &= ~APIC_VECTOR_MASK;
	val &= ~APIC_LVT_MASKED;
	val |= vec;
	apic_write(lvt[i], val);
	mb();

	irq_enable();
	mb();

	val = apic_read(lvt[i]);
	val &= ~APIC_MODE_MASK;
	val |= APIC_DM_SMI;

	apic_write(lvt[i], val);
	err = test_for_exception(GP_VECTOR, lapic_write_delivery_mode_smi, (void *)(lvt[i]));
	(void) err;
	mb();

	nop();
	lapic_busy_wait();

	report("%s", atomic_read(&lapic_timer_isr_count) == 0, msg);
	}
}

/* Summary: 1 Case for Requirement: 146496 Filter the MSI interrupt with illegal vector */
/*    <1: 146496 - 27936> Local APIC_Filter the MSI interrupt with illegal vector_001 */

/**
 * @brief case name Filter the MSI interrupt with illegal vector
 *
 * Summary: When a MSI device is configured with interrupt vector from 0H to FH, the device
 *  or PCI/PCIe controller shall ignore the interrupt delivery.
 *  Tested on platform by configuring the MSI data in MSI capability with illegal
 *  vector, the MSI message is ignored. The LAPIC can not receive this illegal
 *  message. Our hardware platform should follow this common practice.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27936_filter_the_msi_interrupt_with_illegal_vector_001(void)
{
	const char *msg = "MSI Environment is not ready for Local APIC 146496 - 27936";
	report("%s", 0, msg);
}

/* Summary: 2 Case for Requirement: 146598 Read-only LAPIC ID register */
/*    <1: 146598 - 27497> Local APIC_Read-only LAPIC ID register_001 */

static void lapic_read_only_id_fn(void *msg)
{
	const char *report_msg = (const char *)msg;
	wrmsr(LAPIC_MSR(APIC_ID), LAPIC_APIC_ID_VAL);
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

static void lapic_read_only_id_xapic_fn(void *msg)
{
	unsigned long base;
	const char *report_msg = (const char *)msg;
	base = rdmsr(MSR_IA32_APICBASE) & ~0x0FFFUL;
	*((volatile unsigned int *)(base + APIC_ID)) = LAPIC_APIC_ID_VAL;
	LAPIC_NO_EXEC("%s", 0, report_msg);
}

/**
 * @brief case name Read-only LAPIC ID register
 *
 * Summary: ACRN hypervisor shall guarantee that guest LAPIC ID register is read-only.
 *  In compliance with Table 10-6, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27497_read_only_lapic_id_register_001(void)
{
	unsigned long apic_base_status;

	const char *msg =
		"local_apic_rqmid_27497_read_only_lapic_id_register_001";
	int err = 0;

	apic_base_status = rdmsr(MSR_IA32_APICBASE);
	if (!(apic_base_status & APIC_EXTD))
		return;

	err = test_for_exception(GP_VECTOR, lapic_read_only_id_fn, (void *)msg);
	report("%s", err != 0, msg);
}

/*    <2: 146598 - 27493> Local APIC_Read-only LAPIC ID register_002 */

/**
 * @brief case name Read-only LAPIC ID register
 *
 * Summary: ACRN hypervisor shall guarantee that guest LAPIC ID register is read-only.
 *  In compliance with Table 10-6, Vol.3, SDM.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27493_read_only_lapic_id_register_002(void)
{
	static unsigned long apic_base_status;

	static unsigned id1;
	static unsigned id2;


	static const char *msg =
		"local_apic_rqmid_27493_read_only_lapic_id_register_002";
	static int err = 0;

	apic_base_status = rdmsr(MSR_IA32_APICBASE);
	if (!!(apic_base_status & APIC_EXTD))
		return;

	id1 = *((volatile unsigned int *)(base + APIC_ID));
	(void) test_for_exception(GP_VECTOR, lapic_read_only_id_xapic_fn, (void *)msg);
	id2 = *((volatile unsigned int *)(base + APIC_ID));

	report("%s", id1 == id2, msg);
}

/* Summary: 1 Case for Requirement: 148483 CR8 state following start-up */
/*    <1: 148483 - 27925> Local APIC_CR8 state following start-up_001 */

/**
 * @brief case name CR8 state following start-up
 *
 * Summary: ACRN hypervisor shall set initial guest CR8 to 0H following start-up.
 *  CR8 is a mirror of LAPIC TPR and the initial guest LAPIC TPR is 0H.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27925_cr8_state_following_start_up_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_PRIVATE_MEM_ADDR +
				LAPIC_APIC_STRUCT(APIC_CR8)));
	report("%s", val == 0U,
		"local_apic_rqmid_27925_cr8_state_following_start_up_001");
}

/* Summary: 1 Case for Requirement: 148484 CR8 state following INIT */
/*    <1: 148484 - 27924> Local APIC_CR8 state following INIT_001 */

/**
 * @brief case name CR8 state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest CR8 to 0H following INIT.
 *  CR8 is a mirror of LAPIC TPR and the initial guest LAPIC TPR is 0H.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27924_cr8_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_INIT_AP_BASE_ADDR +
				LAPIC_APIC_STRUCT(APIC_CR8)));
	report("%s", val == 0U,
		"local_apic_rqmid_27924_cr8_state_following_init_001");
}

/**
 * @brief case name CR8 state following INIT
 *
 * Summary: ACRN hypervisor shall set initial guest CR8 to 0H following INIT.
 *  CR8 is a mirror of LAPIC TPR and the initial guest LAPIC TPR is 0H.
 *
 *
 * @param None
 *
 * @retval None
 *
 */
void local_apic_rqmid_27926_cr8_state_following_init_001(void)
{
	unsigned val = *((unsigned int *)(LAPIC_INIT_AP_BASE_ADDR +
				LAPIC_APIC_STRUCT(APIC_CR8)));
	report("%s", val == 0U,
		"local_apic_rqmid_27926_cr8_state_following_init_001");
}


// TODO: ADD CR8 mirror of APIC_TPR: 1 case, RQM
#endif

#elif __i386__
/*test case which should run  under 32bit  */

#endif
