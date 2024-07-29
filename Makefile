default: debug

CFLAGS=-Wall -Wextra -pedantic -Wundef -Wshadow -Wpointer-arith -std=c17 -Wconversion

debug:
	gcc -Og -g -ggdb $(CFLAGS) -static ixode.c -DDEBUG -o ixode_debug

release:
	gcc $(CFLAGS) -static ixode.c -o ixode_release
	strip ixode_release

clean:
	rm -f -- ixode_debug ixode_release

.PHONY: default debug release clean