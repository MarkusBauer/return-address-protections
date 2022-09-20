Return Address Protections
==========================

This repository contains free implementations of a software-only shadow stack and return address encryption.
Both defenses protect return addresses on the stack from malicious overwrites, for example, by a stack overflow.
The defenses harden C/C++/Fortran applications for example against ROP attacks.

Read more about shadow stacks [on Wikipedia](https://en.wikipedia.org/wiki/Shadow_stack).
Return address encryption is a part of ["G-Free"](http://doi.acm.org/10.1145/1920261.1920269) by Onarlioglu et al.

- Defenses are implemented as an assembly rewriter for **x86_64**. 
- Compatible with **GCC** 9 and **Clang** 13 (and likely newer versions).
- Tested on Ubuntu **Linux** and Debian.
- Protected programs are compatible with unprotected libraries. 
- Code is a proof of concept, in particular the runtime libraries. Use at your own risk.
- As a proof of concept, the protections are for *single-threaded* programs only. Rewrite the runtime library if you need multithreading.


Setup
-----
Initially, build the runtime libraries: `cd runtime-libs && make`


Usage
-----
First, configure your compiler to use `path/as` as assembler. 
For example, prepend the folder `path` to your path.
You can use `set_path.sh` for this.
For Clang, you also need the flag `-fno-integrated-as`.

Then select one of the protection schemes and pass the flag to your compiler:
- `-Wa,-shadowstack` Shadow Stack
- `-Wa,-ripxoring` Return Address Encryption
- `-Wa,-shadowstack-mem-safety-check` Optimized Shadow Stack
- `-Wa,-ripxoring-mem-safety-check` Optimized Return Address Encryption

Finally, add the necessary runtime library to your program:
- `runtime-libs/shadowstack-lib.o` for shadow stack
- `-Lruntime-libs -lunwind-ripxoring` for return address encryption (only necessary for C++)

Examples:
```shell
# shadow stack
./set_path.sh gcc -c examples/prog1.c -o prog1.o -Wa,-shadowstack
./set_path.sh gcc prog1.o -o prog1 -Wa,-shadowstack runtime-libs/shadowstack-lib.o

# return address encryption
./set_path.sh gcc -c examples/prog1.c -o prog1.o -Wa,-ripxoring
./set_path.sh gcc prog1.o -o prog1 -Wa,-ripxoring -Lruntime-libs -lunwind-ripxoring

# optimized mode(s)
./set_path.sh gcc -c examples/prog1.c -o prog1.o -Wa,-shadowstack-mem-safety-check
./set_path.sh gcc prog1.o -o prog1 -Wa,-shadowstack-mem-safety-check runtime-libs/shadowstack-lib.o

# clang
./set_path.sh /usr/lib/llvm-10/bin/clang -fno-integrated-as -c examples/prog1.c -o prog1.o -Wa,-shadowstack
./set_path.sh /usr/lib/llvm-10/bin/clang -fno-integrated-as prog1.o -o prog1 -Wa,-shadowstack runtime-libs/shadowstack-lib.o
```


Example
-------
We provide an example program (including example attack) in [examples/](examples/).
See the protection's effect:

```shell
cd examples
make

./prog1-ref
# Some general addresses:
# 0x55de7f37a0c0  main
# 0x55de7f37a210  test_attack
# 0x55de7f37a1f0  target
# Stack dump:
# 0x7ffd3343a8f0: 00007ffd3343a8f0
# 0x7ffd3343a8f8: 395ea003e1cfa200
# 0x7ffd3343a900: 000055de7f37a390
# 0x7ffd3343a908: 0000000000000000
# 0x7ffd3343a910: 000055de7f37a100
# 0x7ffd3343a918: 00007ffd3343aa20
# 0x7ffd3343a920: 0000000000000000
# 0x7ffd3343a928: 000055de7f37a0d8  <-- return address
# 0x7ffd3343a930: 000055de7f37a390
# 0x7ffd3343a938: 00007f099e921083
# 0x7ffd3343a940: 00007f099eb59620
# 0x7ffd3343a948: 00007ffd3343aa28

./prog1-ref attack
# 0x7ffd3343a928: 000055de7f37a0d8  <-- return address
# ... overwrite 0x7ffd3343a928 with 0x55de7f37a1f0 ...
# TARGET CALLED!

./prog1-shadowstack attack
# 0x7fff9d3d7648: 0000558de19b51a3  <-- return address
# ... overwrite 0x7fff9d3d7648 with 0x558de19b53a0 ...
# Illegal instruction


./prog1-ripxoring attack
# 0x7ffda40c7838: 82ba2ab0c24e9aef  <-- return address
# ... overwrite 0x7ffda40c7838 with 0x5652331ee220 ...
# Segmentation fault
```


Optimizations
-------------
We provide optimized modes for both schemes that do not instrument "safe" functions.
A function is safe if it cannot overwrite its return address under any circumstances, e.g., because it does not write memory or all memory accesses are relative to `rsp`.
To the best of our knowledge, this optimization does not weaken the security at all but can improve performance.

Use `-Wa,-shadowstack-mem-safety-check` or `-Wa,-ripxoring-mem-safety-check` to enable optimized versions.


Performance
-----------
We measured the following mean performance overhead on SPEC CPU 2017.
Benchmark system was an Intel i5-4690 with 32GB memory.
Overhead on other programs and machines might vary.

| Protection                            | Overhead (C) | Overhead (C++) | Overhead (Fortran) | Overhead (overall) |
|---------------------------------------|--------------|----------------|--------------------|--------------------|
| Shadow Stack                          | 1.3%         | 3.0%           | 0.0%               | 1.5%               |
| Shadow Stack (optimized)              | 1.0%         | 1.7%           | 0.0%               | 0.9%               |
| Return Address Encryption             | 1.6%         | 5.6%           | 0.0%               | 2.5%               |
| Return Address Encryption (optimized) | 1.1%         | 4.5%           | 0.0%               | 1.9%               |


License
-------
The folder `runtime-libs/libunwind` is a modified version of LLVM's libunwind which is licensed under "Apache License v2.0 with LLVM Exceptions" (see [LICENSE.txt](runtime-libs/libunwind/LICENSE.txt)).
We have patched [src/DwarfInstructions.hpp](runtime-libs/libunwind/src/DwarfInstructions.hpp), line 200-210.

The remaining code is licensed under MIT license.
