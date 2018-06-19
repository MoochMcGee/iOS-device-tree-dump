CFLAGS=-g
LIBS=-lssl -lcrypto

all:
	gcc $(CFLAGS) dtdump.c -o dtdump $(LIBS)

clean:
	rm dtdump
