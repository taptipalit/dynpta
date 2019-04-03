CC = /mnt/Projects/LLVM-custom/install/bin/clang
CFLAGS=-O0 -flto
LDFLAGS=-O0 -flto -lhelper -Xclang -dump-consG

main: main.o
	$(CC) $(LDFLAGS) -v main.o -o main -L../ -lssl -lcrypto

main.o:	main.c
	$(CC) -c $(CFLAGS) main.c -o main.o

.PHONY:	clean

clean:
	rm *.o main *.bc *.dot *.png
