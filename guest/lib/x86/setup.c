/*
 * Initialize machine setup information
 *
 * Copyright (C) 2017, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include "libcflat.h"
#include "fwcfg.h"
#include "alloc_phys.h"
#include "apic.h"

extern char bss_start;
extern char edata;

struct mbi_bootinfo {
	u32 flags;
	u32 mem_lower;
	u32 mem_upper;
	u32 boot_device;
	u32 cmdline;
	u32 mods_count;
	u32 mods_addr;
	u32 reserved[5];   /* 28-47 */
	u32 mmap_addr;
	u32 reserved0[3];  /* 52-63 */
	u32 bootloader;
	u32 reserved1[5];  /* 68-87 */
	u32 size;
};

struct mbi_module {
	u32 start, end;
	u32 cmdline;
	u32 unused;
};


#define ENV_SIZE 16384

extern void setup_env(char *env, int size);

char *initrd;
u32 initrd_size;

static char env[ENV_SIZE];

extern unsigned char sipi_cnt;

void bss_init(void)
{
	memset(&bss_start, 0, &edata - &bss_start);
}

void setup_multiboot(struct mbi_bootinfo *bootinfo)
{
	struct mbi_module *mods;

	/* TODO: use e820 */
	u64 end_of_memory = bootinfo->mem_upper * 1024ull;
	phys_alloc_init((uintptr_t) &edata, end_of_memory - (uintptr_t) &edata);

	if (bootinfo->mods_count != 1)
		return;

	mods = (struct mbi_module *)(uintptr_t) bootinfo->mods_addr;

	initrd = (char *)(uintptr_t) mods->start;
	initrd_size = mods->end - mods->start;
}

void setup_libcflat(void)
{
	if (initrd) {
		/* environ is currently the only file in the initrd */
		u32 size = MIN(initrd_size, ENV_SIZE);
		memcpy(env, initrd, size);
		setup_env(env, size);
	}
}
/* --------------------------------------------------------*
*void send_sipi(): send sipi to all aps
*This function will wait AP ;until AP initilize completely
*
*
*----------------------------------------------------------*/
void send_sipi()
{
	unsigned nb_cpus;
	unsigned ap_cpus;
	unsigned char sipi_nb_cnt;

	nb_cpus = fwcfg_get_nb_cpus();
	ap_cpus = nb_cpus - 1;
	sipi_nb_cnt = sipi_cnt;

	/*issue sipi to awake AP */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_DEST_PHYSICAL | APIC_DM_INIT | APIC_INT_ASSERT, 0);
	apic_icr_write(APIC_DEST_ALLBUT | APIC_DEST_PHYSICAL | APIC_DM_INIT , 0);
	apic_icr_write(APIC_DEST_ALLBUT | APIC_DEST_PHYSICAL | APIC_DM_STARTUP , 0);
	/*waiting all aps initilize completely*/
	while ((sipi_nb_cnt + ap_cpus) > sipi_cnt){
		asm volatile("nop");
	}
}

