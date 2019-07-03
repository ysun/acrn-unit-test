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

int main(int ac, char **av)
{
	int ret;
	int detected = 0;
	atomic_set(&begin_sem1, 0);
	atomic_set(&begin_sem2, 0);
	atomic_set(&end_sem1, 0);
	atomic_set(&end_sem2, 0);
	setup_idt();

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

		memset(ARRAY, 0, 1030);
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
			"begin: 			\n\t"
			"    lea ARRAY(,%0,4), %2	\n\t"
			"    movntil  %0, (%2) 		\n\t"
			"    inc   %0			\n\t"
			"    cmp   %1, %0		\n\t"
			"    jle   begin		\n\t"
#if USE_CPU_FENCE
			"sfence\n\t                  "
#endif
			:
			: "r"(r1), "r"(r2), "r"(r3)
			: 
			);

	atomic_inc(&end_sem1);
	pause();
}

void test2() {
	//Sync with test1, right after test1.
	while(atomic_read(&begin_sem2) != 1 || atomic_read(&end_sem1) != 1) NOP();
	atomic_dec(&begin_sem2);

	asm volatile(
			"movl %1, %0\n\t                 "
			: "=r"(r4)
			: "m"(ARRAY[1029])
			: );

	//Test memory re-ordering!!
	if( r4 != 1029)
		printf("ARRAY is reordered! (%d)\n", r4);

	atomic_inc(&end_sem2);
}

