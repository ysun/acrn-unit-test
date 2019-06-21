#include "libcflat.h"
#include "desc.h"
#include "processor.h"

static void test_rsm(void)
{
	printf("%s\n", __FUNCTION__);

	//asm volatile ("rsm");

	asm volatile(ASM_TRY("1f")
	     "rsm \n\t" 
	     "1:":::);

	report("Execute RSM will get #UD", exception_vector() == UD_VECTOR);	


}

int main(void)
{
	setup_vm();
	setup_idt();

	test_rsm();

	return report_summary();
}
