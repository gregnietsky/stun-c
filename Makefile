PREFIX=/usr
BINDIR=$(PREFIX)/bin

CC=gcc
INSTALL=ginstall

all:	stun
distclean:	clean

clean:
	rm stun


install: all
	$(INSTALL) -D stun $(DESTDIR)$(BINDIR)/stun

stun:
	$(CC) stun.c -o stun -lpthread
