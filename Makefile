.PHONY: clean
CFLAGS	= -Wall
LDFLAGS	= -lpcap -lnet

tcpkill: tcpkill.c pcaputil.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

tcpkill6: tcpkill6.c pcaputil.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
clean:
	rm -f pcaputil.o tcpkill tcpkill6
