#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/**
 * A demo application that simulates a ROP attack
 * 
 * If started without parameters, it dumps a function's stack frame.
 * If started with a parameter, it overwrites its return address with another function.
 * All defenses should stop the second case.
 */


void target() {
	puts("TARGET CALLED!");
	_exit(1);
}


void __attribute__((noinline)) test_attack(int x);


int main(int argc, const char *argv[]) {
	test_attack(argc > 1);
	asm("nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop");
	asm("nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop");
	asm("nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop");
	asm("nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop");
	return 0;
}


void __attribute__((noinline)) test_attack(int x) {
	uintptr_t *stackptr;
	stackptr = (void*) &stackptr;
	uintptr_t canary_value;
	asm("movq    %%fs:40, %0" : "=r"(canary_value));

	printf("Some general addresses:\n%p  main\n%p  test_attack\n%p  target\n%lx  canary/encryption key\n", 
		&main, &test_attack, &target, canary_value);
	uintptr_t main_addr = (uintptr_t) &main;

	printf("Stack dump:\n");
	for (int i = 0; i < 12; i++) {
		if ((stackptr[i] > main_addr && stackptr[i] < main_addr + 64) || ((stackptr[i] ^ canary_value) > main_addr && (stackptr[i] ^ canary_value) < main_addr + 64)) {
			printf("%p: %016lx  <-- return address\n", stackptr+i, stackptr[i]);
		} else {
			printf("%p: %016lx\n", stackptr+i, stackptr[i]);
		}
	}

	if (x > 0) {
		for (int i = 0; i < 12; i++) {
		if ((stackptr[i] > main_addr && stackptr[i] < main_addr + 64) || ((stackptr[i] ^ canary_value) > main_addr && (stackptr[i] ^ canary_value) < main_addr + 64)) {
			printf("... overwrite %p with %p ...\n", stackptr+i, &target);
			stackptr[i] = (uintptr_t) &target;
		}
	}
	}
}
