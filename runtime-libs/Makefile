all: shadowstack-lib.o libunwind_static

libcxx:
	wget "https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.0/libcxx-13.0.0.src.tar.xz" -Olibcxx-13.0.0.src.tar.xz
	tar -xf libcxx-13.0.0.src.tar.xz
	rm -f libcxx-13.0.0.src.tar.xz
	mv libcxx-13.0.0.src libcxx

llvm:
	wget "https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.0/llvm-13.0.0.src.tar.xz" -Ollvm-13.0.0.src.tar.xz
	tar -xf llvm-13.0.0.src.tar.xz
	rm -f llvm-13.0.0.src.tar.xz
	mv llvm-13.0.0.src llvm

shadowstack-lib.o: shadowstack-lib.c
	@gcc -c shadowstack-lib.c -o shadowstack-lib.o -Os

libunwind-build: libcxx llvm
	mkdir -p libunwind-build
	cd libunwind-build && cmake ../libunwind -DLIBUNWIND_ENABLE_SHARED=OFF -DCMAKE_BUILD_TYPE=MinSizeRel -DLLVM_PATH=../llvm

libunwind_static: libunwind-build
	cd libunwind-build && make unwind_static
	cp libunwind-build/lib/libunwind.a ./libunwind-ripxoring.a

clean:
	rm -rf *.o libunwind-build
