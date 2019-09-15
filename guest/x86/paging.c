#include "libcflat.h"
#include "desc.h"
#include "processor.h"
#include "paging.h"
#include "vm.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "alloc_phys.h"
#include "alloc.h"
#include "misc.h"

static int test_instruction_fetch(void *p)
{
	asm volatile(ASM_TRY("1f")
		 "call *%[addr]\n\t"
		 "1:"
		 : : [addr]"r"(p));

	return exception_vector();
}

static void free_gva(void *gva)
{
	set_page_control_bit(gva, PAGE_PTE, PAGE_P_FLAG, 1, true);
	free(gva);
	gva = NULL;
}

static bool check_value_is_exist(u32 reg, u8 value)
{
	u32 i;

	for (i = 0; i < 4; i++) {
		if (((u8)(reg >> (i * 8)) & 0xff) == value) {
			return true;
		}
	}

	return false;
}

/*
 * Case name:Encoding of CPUID Leaf 2 Descriptors_001
 *
 * Summary: check TLB information in CPUID.02H. Because the order of descriptors
 *          in the EAX, EBX, ECX, and EDX registers is not defined,
 *          the descriptors may appear in any order. While checking CPUID:02 registers,
 *          the return value may be disordered while comparing with default value.
 *          So we will check each different "8bit value" if exists
 *          in EAX/EBX/ECX/EDX, and not care it's order.
 */
static void paging_rqmid_23896_check_tlb_info()
{
	struct cpuid r= cpuid(2);
	u8 tlb_info[8] = {TYPE_TLB_01, TYPE_TLB_03, TYPE_TLB_63, TYPE_TLB_76,
				TYPE_TLB_B6, TYPE_STLB_C3,
				TYPE_PREFECTH_F0, TYPE_GENEAL_FF};
	u32 cpuid_value[4] = {r.a, r.b, r.c, r.d};
	u32 exist_num = 0;
	u32 i;
	u32 j;

	for (j = 0; j < 8; j++) {
		for (i = 0; i < 4; i++) {
			if (check_value_is_exist(cpuid_value[i], tlb_info[j])) {
				exist_num++;
				break;
			}
		}
	}

	report("paging_rqmid_23896_check_tlb_info", (exist_num == 8));
}

/*
 * Case name:Hide Processor Context Identifiers_001
 *
 * Summary: When process-context identifiers are hidden, CPUID.01H:ECX.
 * 	    PCID [bit 17] shall be 0, and changing CR4.PCIDE from 0 to 1,shall generate #GP.
 */
static void paging_rqmid_23897_hide_processor_context_identifiers()
{
	unsigned long cr4 = read_cr4();
	bool is_pass = false;

	if ((cpuid(1).c & (1 << 17)) == 0) {
		if (write_cr4_exception_checking(cr4 | X86_CR4_PCIDE) == GP_VECTOR) {
			is_pass = true;
		}
	}

	report("paging_rqmid_23897_hide_processor_context_identifiers", is_pass);
}

/*
 * Case name:Global Pages Support_001
 *
 * Summary: Execute CPUID.01H:EDX.PGE [bit 13] shall be 1, set CR4.PGE to enable
 * 	    global-page feature shall have no exception
 */
static void paging_rqmid_23901_global_pages_support()
{
	unsigned long cr4 = read_cr4();
	bool is_pass = false;

	if ((cpuid(1).c & (1 << 13)) != 0) {
		if (write_cr4_exception_checking(cr4 | X86_CR4_PGE) == PASS) {
			if ((read_cr4() & X86_CR4_PGE) != 0) {
				is_pass = true;
			}
		}
	}

	report("paging_rqmid_23901_global_pages_support", is_pass);
}

/*
 * Case name:CPUID.80000008H:EAX[7:0]_001
 *
 * Summary: Execute CPUID.80000008H:EAX[7:0] to get the physical-address width
 * 	    supported by the processor, it shall be 39.
 */
static void paging_rqmid_23895_check_physical_address_width()
{
	bool is_pass = false;

	if ((cpuid(0x80000008).a & 0xff) == PHYSICAL_ADDRESS_WIDTH) {
		is_pass = true;

	}

	report("paging_rqmid_23895_check_physical_address_width", is_pass);
}

#ifdef __x86_64__
/* test case which should run under 64bit */
#include "64/paging_fn.c"
#elif __i386__
/* test case which should run  under 32bit */
#include "32/paging_fn.c"
#endif

static void test_paging()
{
	paging_rqmid_23896_check_tlb_info();
	paging_rqmid_23897_hide_processor_context_identifiers();
	paging_rqmid_23895_check_physical_address_width();
#ifdef __x86_64__
	test_paging_64bit_mode();
#elif __i386__
	test_paging_32bit_mode();
#endif
	paging_rqmid_23901_global_pages_support();
}

static void print_case_list()
{
	printf("paging feature case list:\n\r");
	printf("\t\t Case ID:%d case name:%s\n\r", 23896u, "Encoding of CPUID Leaf 2 Descriptors_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 23897u, "Hide Processor Context Identifiers_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 23895u, "CPUID.80000008H:EAX[7:0]_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 23901u, "Global Pages Support_001");
#ifdef __x86_64__
	printf("\t\t Case ID:%d case name:%s\n\r", 24522u, "TLB Support_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 23918u, "Write Protect Support_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 23912u, "Hide Invalidate Process-Context Identifier_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 24519u, "Invalidate TLB When vCPU writes CR3_disable global paging_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 26017u, "Supervisor Mode Execution Prevention Support_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 24460u, "Invalidate TLB When vCPU changes CR4.SMAP_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 23917u, "Protection Keys Hide_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 26827u, "Invalidate TLB When vCPU writes CR3_enable global paging_002");
#elif __i386__
	printf("\t\t Case ID:%d case name:%s\n\r", 24415u, "32-Bit Paging Support_001");
	printf("\t\t Case ID:%d case name:%s\n\r", 25249u, "Execute Disable support_001");

#endif
}

int main(void)
{
	setup_idt();
	setup_vm();

	print_case_list();
	test_paging();

	return report_summary();
}

