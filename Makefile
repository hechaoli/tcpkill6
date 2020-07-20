CFLAGS	= -Wall
LDFLAGS	= -lpcap -lnet

phony =
binaries =


tcpkill: tcpkill.c pcaputil.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
binaries += tcpkill

tcpkill6: tcpkill6.c pcaputil.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
binaries += tcpkill6



all: install | $(binaries)
phony += all

install:
	xargs -a dependencies sudo apt-get install
phony += install

clean:
	rm -f pcaputil.o tcpkill tcpkill6
phony += clean


.PHONY: $(phony)
.DEFAULT_GOAL := all
