/*
 * Test for x86 cache and memory instructions
 *
 * Copyright (c) 2019 Intel
 *
 * Authors:
 *  Yi Sun <yi.sun@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "libcflat.h"
#include "desc.h"
#include "processor.h"

#include "asm/spinlock.h"
#include "atomic.h"

#include "alloc.h"

#define USE_CPU_FENCE  0
#define MAX_RUNNING_CPU 3
#define NOP()       do { asm volatile ("nop\n\t" :::); } while(0)

void ap_main();
void test1();
void test2();
void (*test_cases[MAX_RUNNING_CPU])() = { NULL, test1, test2 };

atomic_t begin_sem1;
atomic_t begin_sem2;
atomic_t end_sem1;
atomic_t end_sem2;

int X, Y;
int ARRAY[1030];
//int *ARRAY;
int r1, r2;
int r3, r4;
int id;

int logical_processor_arbitration() {
    int id;

    static int __booting_id = 1;    // share with cpus_booted; AP from 1, 0 is BP
    static struct spinlock cpu_id_lock = {0};
    spin_lock(&cpu_id_lock);
        id = __booting_id;
        ++__booting_id;

	printf("arbitration id: %d\n", id);
    spin_unlock(&cpu_id_lock);
    return id;
}
#define CR0_BIT_NW              29
#define CR0_BIT_CD              30
#define CR0_BIT_PG              31

#define MSR_IA32_CR_PAT_TEST                    0x00000277
#define IA32_MISC_ENABLE                                0x000001A0
#define IA32_MTRR_DEF_TYPE                              0x000002FF
#define IA32_MTRRCAP_MSR                                0x000000FE
#define IA32_SMRR_PHYSBASE_MSR                  0x000001F2
#define IA32_SMRR_PHYSMASK_MSR                  0x000001F3

void disable_MTRR()
{
        u64 msr_value;

        msr_value = rdmsr(IA32_MTRR_DEF_TYPE);
        msr_value = msr_value&(~(1<<11));
        wrmsr(IA32_MTRR_DEF_TYPE,msr_value);
        printf("IA32_MTRR_DEF_TYPE 0x%lx set=0x%lx\n",
                rdmsr(IA32_MTRR_DEF_TYPE), msr_value);
}
void enable_MTRR()
{
        u64 msr_value;

        msr_value = rdmsr(IA32_MTRR_DEF_TYPE);
        msr_value = msr_value|(1<<11);
        wrmsr(IA32_MTRR_DEF_TYPE,msr_value);
        printf("IA32_MTRR_DEF_TYPE 0x%lx set=0x%lx\n",
                rdmsr(IA32_MTRR_DEF_TYPE), msr_value);
}

void cache_test_mfence_wbinvd()
{
        asm volatile("mfence" ::: "memory");
        asm volatile ("   wbinvd\n" : : : "memory");
        asm volatile("mfence" ::: "memory");
}
void write_cr0_bybit(u32 bit, u32 bitvalue)
{
        u32 cr0 = read_cr0();
        if (bitvalue) {
                write_cr0(cr0 | (1 << bit));
        } else {
                write_cr0(cr0 & ~(1 << bit));
        }
}
void cache_test_wbinvd()
{
        asm volatile ("wbinvd\n" : : : "memory");
}

void flush_tlb()
{
        u32 cr3;
        cr3 = read_cr3();
        write_cr3(cr3);
}

void mem_cache_reflush_cache()
{

        u32 cr4;
        //write_cr4_bybit(CR4_BIT_PGE, 1);
        //cr4  = read_cr4();
        //debug_print("cr4.PGE=%d cr4.PAE=%d\n", cr4&(1<<CR4_BIT_PGE)?1:0, cr4&(1<<CR4_BIT_PAE)?1:0);

        //disable interrupts;
        irq_disable();

        //Save current value of CR4;
        cr4 = read_cr4();

        //disable and flush caches;
        write_cr0_bybit(CR0_BIT_CD, 1);
        write_cr0_bybit(CR0_BIT_NW, 0);
        cache_test_wbinvd();

        //flush TLBs;
        flush_tlb();

        //disable MTRRs;
        disable_MTRR();

        //flush caches and TLBs
        cache_test_wbinvd();
        flush_tlb();

        //enable MTRRs;
        enable_MTRR();

        //enable caches
        write_cr0_bybit(CR0_BIT_CD, 0);
        write_cr0_bybit(CR0_BIT_NW, 0);

        //restore value of CR4;
        write_cr4(cr4);

        //enable interrupts;
        irq_enable();
}

void mem_cache_test_set_type_all(u64 cache_type)
{
        u64 ia32_pat_test;

        wrmsr(MSR_IA32_CR_PAT_TEST,cache_type);

        ia32_pat_test = rdmsr(MSR_IA32_CR_PAT_TEST);
        printf("ia32_pat_test 0x%lx \n",ia32_pat_test);

        if(ia32_pat_test != cache_type)
                printf("set pat type all error set=0x%lx, get=0x%lx\n", cache_type, ia32_pat_test);
        else
                printf("set pat type all sucess type=0x%lx\n", cache_type);

        cache_test_mfence_wbinvd();

        mem_cache_reflush_cache();
}
unsigned long long rdtsc_test(void)
{
        long long r;

#ifdef __x86_64__
        unsigned a, d;
        asm volatile("mfence" ::: "memory");
        asm volatile ("rdtsc" : "=a"(a), "=d"(d));
        r = a | ((long long)d << 32);
#else
        asm volatile ("rdtsc" : "=A"(r));
#endif
        asm volatile("mfence" ::: "memory");
        return r;
}
static inline void maccess(u64 *p)
{
  //asm volatile("mfence" ::: "memory");
  asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
  //asm volatile("mfence" ::: "memory");
}

static void wraccess(unsigned long address, unsigned long value)
{
        asm volatile("mov %[value], (%[address])"
                     :
                     : [value]"r"(value), [address]"r"(address)
                     : "memory");
        //asm volatile("mfence" ::: "memory");
}
void mem_cache_test_write(u64 size)
{
        u64 index;
        u64 t[2] = {0};
        u64 t_total=0;

        t[0] = rdtsc_test();
        for(index=0; index<size; index++){
                wraccess((unsigned long )&ARRAY[index], index);
        }
        t[1] = rdtsc_test();
        t_total += t[1] - t[0];

        printf("%ld\n", t_total);
        asm volatile("mfence" ::: "memory");
}

void mem_cache_test_write_time_invd(u64 size, int time)
{
        printf("write cache cache_test_size 0x%lx %ld\n",size, size*8);

        while(time--){
                mem_cache_test_write(size);
        }

        cache_test_mfence_wbinvd();
}

int main(int ac, char **av)
{
	int ret;
	int detected = 0;
	atomic_set(&begin_sem1, 0);
	atomic_set(&begin_sem2, 0);
	atomic_set(&end_sem1, 0);
	atomic_set(&end_sem2, 0);
	setup_idt();

	//default PAT entry value 0007040600070406
	mem_cache_test_set_type_all(0x0000000001040501); //00: UC 06: WB 01:WC
	//ARRAY = (int *)malloc(1030 * 4);

	mem_cache_test_write_time_invd(1030 / 2, 2);
	id = 0;

	for (int i = 1;  ; ++i) {
		X = Y = 0;
		r1 = r2 = 0;

		atomic_inc(&begin_sem1);
		atomic_inc(&begin_sem2);

		while(atomic_read(&end_sem1) != 1 || atomic_read(&end_sem2) != 1) NOP();
		atomic_set(&end_sem1, 0);
		atomic_set(&end_sem2, 0);

		if (ARRAY[1029] != 1029) {
			detected++;
			printf("%d reorders detected after %d iterations\n", detected, i);
		}

		if( i % 10000 == 0) printf("BSP: times %d\n", i);

		memset(ARRAY, 0, 1030*4);
		//make sure ARRAY is clear.
		asm volatile("mfence":::"memory");
	}

	ret = report_summary();

	while(1) { NOP(); }
	return ret;
}
void ap_main() {
	int local_id = logical_processor_arbitration();

	if (local_id >= MAX_RUNNING_CPU) {
		printf("<HALT *AP* > un-used processor id %d\n", local_id);
		while(1) { NOP(); }
	} else {
		printf("<Enter *AP* > processor id %d\n", local_id);
	}

	while(1)
		test_cases[local_id]();
}

void test1() {
	while(atomic_read(&begin_sem1) != 1) NOP();
	atomic_dec(&begin_sem1);

/* create a array by MOVNTI instruction:
    ARRAY[0] = 0;
    ARRAY[1] = 1;
    ...
    ARRAY[1022] = 1022;
    ARRAY[1023] = 1023;
*/
	asm volatile(
			"movl $0, %0			\n\t"
			"movl $1029, %1			\n\t"
//			"movl ARRAY, %%edx			\n\t"
			"begin: 			\n\t"
			"    lea ARRAY(,%0,4), %2	\n\t"
			"    movntil  %0, (%2) 		\n\t"
//			"    movntil  %0, (%%edx, %0, 4) 		\n\t"
			"    inc   %0			\n\t"
			"    cmp   %1, %0		\n\t"
			"    jle   begin		\n\t"
#if USE_CPU_FENCE
			"sfence\n\t                  "
#endif
			:
			: "r"(r1), "r"(r2), "r"(r3)
			: "edx"
			);
/*
	for(int j = 0; j < 1030; j++) {
		if( j % 16 == 0) printf("\n");
		printf("%03d ", ARRAY[j]);
	}
*/
	atomic_inc(&end_sem1);
	pause();
}

void test2() {
	//Sync with test1, right after test1.
	while(atomic_read(&begin_sem2) != 1 || atomic_read(&end_sem1) != 1) NOP();
	atomic_dec(&begin_sem2);

	asm volatile(
//			"movl ARRAY, %%ebx	\n\t                 "
			"movl $1029, %%ecx	\n\t                 "
//			"movl (%%ebx, %%ecx, 0x4), %0\n\t                 "
			"movl ARRAY(, %%ecx, 4), %0\n\t                 "
			: "=r"(r4)
			: 
			: "ebx", "ecx");

	//Test memory re-ordering!!
	if( r4 != 1029)
		printf("ARRAY is reordered! (%d)\n", r4);

	atomic_inc(&end_sem2);
}

