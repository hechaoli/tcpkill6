.PHONY: clean
CFLAGS	= -Wall
LDFLAGS	= -lpcap -lnet

tcpkill: tcpkill.c pcaputil.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tcpkill6: tcpkill6.c pcaputil.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
clean:
	rm -f pcaputil.o tcpkill tcpkill6
