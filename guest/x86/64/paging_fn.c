
static void map_first_16m_supervisor_pages()
{
	/* Map first 16MB as supervisor pages */
	unsigned long i;
	for (i = 0; i < USER_BASE; i += PAGE_SIZE) {
		*get_pte(phys_to_virt(read_cr3()), phys_to_virt(i)) &= ~PT_USER_MASK;
		invlpg((void *)i);
	}

}

static int read_memory_checking(void *p)
{
	u64 value = 1;
	asm volatile(ASM_TRY("1f")
		     "mov (%[p]), %[value]\n\t"
		     "1:"
		     : : [value]"r"(value), [p]"r"(p));
	return exception_vector();
}

/*
 * Case name:Write Protect Support_001
 *
 * Summary: when write CR0.WP is 0, writing value to supervisor-mode address shall
 * be successful for supervisor access.The case is pass when write data success
 */
static void paging_rqmid_23918_write_protect_support()
{
	u8 *p = malloc(1);
	if (p == NULL) {
		printf("malloc error!\n");
		return;
	}

	write_cr0(read_cr0() & ~X86_CR0_WP);
	set_page_control_bit((void *)p, PAGE_PTE, PAGE_USER_SUPER_FLAG, 1, true);

	*p = 2;
	report("paging_rqmid_23918_write_protect_support", (*p == 2));

	free_gva((void *)p);
}

/*
 * Case name:TLB Support_001
 *
 * Summary:Config 4-level paging structure, then write value to gva1, after clear P bit in PTE related with gva1.
 *         we still can access gva1 normally for paging frame information is cached in TLB.
 *         The case is pass when write value to 1B memory pointed by GVA
 */
static void paging_rqmid_24522_tlb_support()
{
	u8 *p = malloc(1);
	if (p == NULL) {
		printf("malloc error!\n");
		return;
	}
	*p = 1;

	set_page_control_bit((void *)p, PAGE_PTE, PAGE_P_FLAG, 0, false);

	*p = 2;
	report("paging_rqmid_24522_tlb_support", (*p == 2));

	free_gva((void *)p);
}

/*
 * Case name:Supervisor Mode Execution Prevention Support_001
 *
 * Summary: When CR4.SMEP,IA32_EFER.NXE are 0 and use user-mode pages,execute RET instruction
 *                shall have no exception. The case passed when execute RET instruction successful
 */
static void paging_rqmid_26017_smep_support()
{
	u64 ia32_efer = rdmsr(X86_IA32_EFER);
	const char *temp = "\xC3";
	void *p = malloc(4);
	if (p == NULL) {
		printf("malloc error!\n");
		return;
	}

	wrmsr(X86_IA32_EFER, ia32_efer | X86_IA32_EFER_NXE);
	memcpy(p, temp, sizeof(temp));

	report("paging_rqmid_26017_smep_support", test_instruction_fetch(p) == PASS);

	free_gva((void *)p);
}

/*
 * Case name:Protection Keys Hide_001
 *
 * Summary: changing CR4.PKE from 0 to 1 shall generate #GP.
 *		  If test results are same with expected result, the test case pass, otherwise, the test case fail.
 */
static void paging_rqmid_23917_protection_keys_hide()
{
	unsigned long cr4 = read_cr4();
	bool is_pass = false;

	if ((cpuid(7).c & (1 << 3)) == 0) {
		if (write_cr4_exception_checking(cr4 | X86_CR4_PKE) == GP_VECTOR) {
			is_pass = true;
		}
	}

	report("paging_rqmid_23917_protection_keys_hide", is_pass);
}

/*
 * Case name:Invalidate TLB When vCPU writes CR3_disable global paging_001
 *
 * Summary: Writing CR3 will invalidate all TLB entries while disabling
 *		  global page and process-context identifiers. Read the 1B memory
 *		  pointed by GVA shall success.
 *		  If test results are same with expected result, the test case pass, otherwise, the test case fail.
 */
static void paging_rqmid_24519_disable_global_paging()
{
	unsigned long cr4 = read_cr4();
	u8 *gva = malloc(sizeof(u8));
	u8 result = 0;
	if (gva == NULL) {
		printf("malloc error!\n");
		return;
	}
	*gva = 0x12;

	write_cr4(cr4 & ~X86_CR4_PCIDE);
	write_cr4(read_cr4() & ~X86_CR4_PGE);

	set_page_control_bit((void *)gva, PAGE_PTE, PAGE_P_FLAG, 0, false);
	if (*gva == 0x12) {
		result++;
	}

	write_cr3(read_cr3());
	if (read_memory_checking((void *)gva) == PF_VECTOR) {
		result++;
	}

	report("paging_rqmid_24519_disable_global_paging", (result == 2));

	free_gva((void *)gva);
}

/*
 * Case name:Invalidate TLB When vCPU writes CR3_enable global paging_002
 *
 * Summary: Writing CR3 won't invadidate TLB enties related with global page
 * 		  hile disabling process-context identifiers. read global pages shall success.
 *		  If test results are same with expected result, the test case pass, otherwise, the test case fail.
 */
static void paging_rqmid_26827_enable_global_paging()
{
	unsigned long cr4 = read_cr4();
	u8 *gva = malloc(sizeof(u8));
	u8 result = 0;
	if (gva == NULL) {
		printf("malloc error!\n");
		return;
	}
	*gva = 0x12;

	write_cr4(cr4 & ~X86_CR4_PCIDE);

	/* check supported for enable global paging */
	if ((cpuid(1).d & (1u << 13)) != 0) {
		write_cr4(cr4 | X86_CR4_PGE);
		result++;
	}

	//set_page_control_bit((void *)gva, PAGE_PTE, PAGE_PTE_GLOBAL_PAGE_FLAG, 1, true);
	if (*gva == 0x12) {
		result++;
	}

	set_page_control_bit((void *)gva, PAGE_PTE, PAGE_P_FLAG, 0, false);
	write_cr3(read_cr3());
	if (*gva == 0x12) {
		result++;
	}

	report("paging_rqmid_26827_write_cr3_global_paging", (result == 3));

	set_page_control_bit((void *)gva, PAGE_PTE, PAGE_PTE_GLOBAL_PAGE_FLAG, 0, true);
	free_gva((void *)gva);
}

/*
 * Case name:Invalidate TLB When vCPU changes CR4.SMAP_001
 *
 * Summary: Config 4-level paging structure, then write?value to gva1,
 *          after clear P bit in PTE related with gva1. we still can access gva1
 *          normally for paging frame information is cached in TLB. After changing CR4.SMAP,
 *          we will get #PF because TLB is invalidated and get PTE directly from memory.
 */
static void paging_rqmid_24460_cr4_smap_invalidate_tlb()
{
	unsigned long cr4 = read_cr4();
	u8 *gva = malloc(sizeof(u8));
	u8 result = 0;
	if (gva == NULL) {
		printf("malloc error!\n");
		return;
	}

	map_first_16m_supervisor_pages();
	*gva = 0x12;

	set_page_control_bit((void *)gva, PAGE_PTE, PAGE_P_FLAG, 0, false);
	if (*gva == 0x12) {
		result++;
	}

	write_cr4(cr4 | X86_CR4_SMAP);
	if (read_memory_checking((void *)gva) == PF_VECTOR) {
		result++;
	}

	report("paging_rqmid_24460_cr4_smap_invalidate_tlb", (result == 2));
}

struct page_invpcid_desc {
    unsigned long pcid : 12;
    unsigned long rsv  : 52;
    unsigned long addr : 64;
};

static int page_invpcid_checking(unsigned long type, void *desc)
{
    asm volatile (ASM_TRY("1f")
                  ".byte 0x66,0x0f,0x38,0x82,0x18 \n\t" /* invpcid (%rax), %rbx */
                  "1:" : : "a" (desc), "b" (type));
    return exception_vector();
}

/*
 * Case name:Hide Invalidate Process-Context Identifier_001
 *
 * Summary:Execute CPUID.(EAX=7,ECX=0):EBX[bit 10] shall be 0, execute INVPCIDE shall generate #UD.
 */
static void paging_rqmid_23912_hide_invalidate_processor_context_identifiers()
{
	struct page_invpcid_desc desc;
	bool is_pass = false;

	if ((cpuid(7).c & (1 << 10)) == 0) {
		if (page_invpcid_checking(2, &desc) == UD_VECTOR) {
			is_pass = true;
		}
	}

	report("paging_rqmid_23912_hide_invalidate_processor_context_identifiers", is_pass);
}

void test_paging_64bit_mode()
{
	u32 case_id = 1;
	switch (case_id) {
	case 1:
		paging_rqmid_23912_hide_invalidate_processor_context_identifiers();
		paging_rqmid_23918_write_protect_support();
		paging_rqmid_24522_tlb_support();
		paging_rqmid_24519_disable_global_paging();
		paging_rqmid_26017_smep_support();
		paging_rqmid_24460_cr4_smap_invalidate_tlb();
		paging_rqmid_23917_protection_keys_hide();
		break;
	case 2:
		paging_rqmid_26827_enable_global_paging();
		break;
	}
}

