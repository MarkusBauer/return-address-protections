all: shadowstack-lib.o libunwind_static

shadowstack-lib.o: shadowstack-lib.c
	@gcc -c shadowstack-lib.c -o shadowstack-lib.o -Os

libunwind-build:
	mkdir -p libunwind-build
	cd libunwind-build && cmake ../libunwind -DLIBUNWIND_ENABLE_SHARED=OFF -DCMAKE_BUILD_TYPE=MinSizeRel -DLLVM_PATH=../../../llvm-source/llvm

libunwind_static: libunwind-build
	cd libunwind-build && make unwind_static
	cp libunwind-build/lib/libunwind.a ./libunwind-ripxoring.a
