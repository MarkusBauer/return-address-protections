
CC=gcc
OPT=-O2

all: prog1-ref prog1-shadowstack prog1-ripxoring prog1-shadowstack-opt prog1-ripxoring-opt


clean:
	rm -rf *.o prog1-*


prog1-ref: prog1.c
	${CC} ${OPT} -c prog1.c -o prog1-ref.o
	${CC} ${OPT} prog1-ref.o -o prog1-ref

prog1-shadowstack: prog1.c
	../set_path.sh ${CC} ${OPT} -c prog1.c -o prog1-shadowstack.o -Wa,-shadowstack
	../set_path.sh ${CC} ${OPT} prog1-shadowstack.o -o prog1-shadowstack ../runtime-libs/shadowstack-lib.o

# ripxoring = return address encryption
prog1-ripxoring: prog1.c
	../set_path.sh ${CC} ${OPT} -c prog1.c -o prog1-ripxoring.o -Wa,-ripxoring
	../set_path.sh ${CC} ${OPT} prog1-ripxoring.o -o prog1-ripxoring -L../runtime-libs -lunwind-ripxoring

prog1-shadowstack-opt: prog1.c
	../set_path.sh ${CC} ${OPT} -c prog1.c -o prog1-shadowstack-opt.o -Wa,-shadowstack-mem-safety-check
	../set_path.sh ${CC} ${OPT} prog1-shadowstack-opt.o -o prog1-shadowstack-opt ../runtime-libs/shadowstack-lib.o

prog1-ripxoring-opt: prog1.c
	../set_path.sh ${CC} ${OPT} -c prog1.c -o prog1-ripxoring-opt.o -Wa,-ripxoring-mem-safety-check
	../set_path.sh ${CC} ${OPT} prog1-ripxoring-opt.o -o prog1-ripxoring-opt -L../runtime-libs -lunwind-ripxoring
