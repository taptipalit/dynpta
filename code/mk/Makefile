CFLAGS  ?=
LDFLAGS ?=

test1.o: test1.c
	$(CC) $(CFLAGS) -c test1.c  $(LDFLAGS) 

test2.o: test2.c
	$(CC) $(CFLAGS) -c test2.c  $(LDFLAGS)

test : test1.o test2.o
	$(CC) $(CFLAGS) test1.o test2.o  $(LDFLAGS) 
