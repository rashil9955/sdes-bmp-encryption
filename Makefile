all: bmper

bmper: bmper.c sdes.c sdes.h
	$(CC) $(CFLAGS) bmper.c sdes.c -o bmper

clean:
	rm -f bmper