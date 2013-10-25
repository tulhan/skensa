CC=gcc
CFLAGS=-std=gnu99 -O -Wall -Wextra -pedantic -lssl -lcrypto

skensa: skensa.o
	$(CC) -o skensa.exe skensa.o $(CFLAGS)

skensa.o: skensa.c
	$(CC) -c -o skensa.o skensa.c $(CFLAGS)

clean:
	rm -f *.o *.exe *.stackdump
