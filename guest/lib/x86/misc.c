#include "vm.h"
#include "libcflat.h"
#include "processor.h"
#include "misc.h"
#include "desc.h"

/**
 * @brief set paging-structure control bit
 *
 * change paging-structure control bit only for 4-level paging mode and 32-bit paging mode
 *
 * @param param_1: the address guest virtual address
 * @param param_2: paging level
 * @param param_3: paging control bit
 * @param param_4: the set value
 * @param param_5: whether invalidate TLB and paging-structure caches
 *
 */

void set_page_control_bit(void *gva,
	page_level level, page_control_bit bit, u32 value, bool is_invalidate)
{
	if (gva == NULL) {
		printf("this address is NULL!\n");
		return;
	}

	ulong cr3 = read_cr3();
#ifdef __x86_64__
	u32 pdpte_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PDPTE);
	u32 pml4_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PML4);
	u32 pd_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PDE);
	u32 pt_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PTE);
	pteval_t *pml4 = (pteval_t *)cr3;

	pteval_t *pdpte = (pteval_t *)(pml4[pml4_offset] & PAGE_MASK);
	pteval_t *pd = (pteval_t *)(pdpte[pdpte_offset] & PAGE_MASK);
	pteval_t *pt = (pteval_t *)(pd[pd_offset] & PAGE_MASK);

	switch (level) {
	case PAGE_PML4:
		if (value == 1) {
			pml4[pml4_offset] |= (1ull << bit);
		} else {
			pml4[pml4_offset] &= ~(1ull << bit);
		}
		break;
	case PAGE_PDPTE:
		if (value == 1) {
			pdpte[pdpte_offset] |= (1ull << bit);
		} else {
			pdpte[pdpte_offset] &= ~(1ull << bit);
		}
		break;
	case PAGE_PDE:
		if (value == 1) {
			pd[pd_offset] |= (1ull << bit);
		} else {
			pd[pd_offset] &= ~(1ull << bit);
		}
		break;
	default:
		if (value == 1) {
			pt[pt_offset] |= (1ull << bit);
		} else {
			pt[pt_offset] &= ~(1ull << bit);
		}
		break;
	}

#else
	u32 pde_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PDE);
	u32 pte_offset = PGDIR_OFFSET((uintptr_t)gva, PAGE_PTE);
	pteval_t *pde = (pgd_t *)cr3;

	pteval_t *pte = (pteval_t *)(pde[pde_offset] & PAGE_MASK);

	if (level == PAGE_PDE) {
		if (value == 1) {
			pde[pde_offset] |= (1u << bit);
		} else {
			pde[pde_offset] &= ~(1u << bit);
		}
	} else {
		if (value == 1) {
			pte[pte_offset] |= (1u << bit);
		} else {
			pte[pte_offset] &= ~(1u << bit);
		}
	}
#endif
	if (is_invalidate) {
		invlpg(gva);
	}

}

int write_cr4_exception_checking(unsigned long val)
{
	asm volatile(ASM_TRY("1f")
			"mov %0,%%cr4\n\t"
			"1:": : "r" (val));
	return exception_vector();
}

int rdmsr_checking(u32 MSR_ADDR, u64 *result)
{
	u32 eax;
	u32 edx;

	asm volatile(ASM_TRY("1f")
		     "rdmsr \n\t"
		     "1:"
		     : "=a"(eax), "=d"(edx): "c"(MSR_ADDR));
	*result = eax + ((u64)edx << 32);
	return exception_vector();
}

int wrmsr_checking(u32 MSR_ADDR, u64 value)
{
	u32 edx = value >> 32;
	u32 eax = value;

	asm volatile(ASM_TRY("1f")
		     "wrmsr \n\t"
		     "1:"
		     : : "c"(MSR_ADDR), "a"(eax), "d"(edx));
	return exception_vector();
}

