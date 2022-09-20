#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>


#define OFFSET (-0x70000000l)
#define NUM_PAGES_BELOW (4096*16)
#define NUM_PAGES_ABOVE (1024*16)


	static __attribute__((constructor)) void ___initialize_shadow_stack(){
		/*void* p;
		__asm__(
		"movq %%rsp, %0;\n"
		 : "=r"(p)); //*/
		int pagesize = sysconf(_SC_PAGE_SIZE);
		uintptr_t shadowaddr = (uintptr_t) &pagesize;
		shadowaddr += OFFSET;
		shadowaddr = shadowaddr & ~((uintptr_t) pagesize-1);
		//fprintf(stderr, "Reserving at %p (rsp = %p)...\n", (void*) shadowaddr, p);
		if (mmap((void*) (shadowaddr-(NUM_PAGES_BELOW)*pagesize), pagesize*(NUM_PAGES_ABOVE+NUM_PAGES_BELOW), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_GROWSDOWN, -1, 0) == MAP_FAILED){
			fprintf(stderr, "Could not reserve shadow stack page (+0x%lx)!\n", OFFSET);
			fprintf(stderr, "%d - %s\n", errno, strerror(errno));
			abort();
		}
	}
