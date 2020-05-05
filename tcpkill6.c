/*
  tcpkill.c

  Kill TCP connections already in progress.

  Copyright (c) 2000 Dug Song <dugsong@monkey.org>

  $Id: tcpkill.c,v 1.15 2000/11/30 00:39:05 dugsong Exp $
*/

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>
#include "pcaputil.h"

/* XXX - brute force seqnum space. ugh. */
#define DEFAULT_SEVERITY	3
#define MAX_CHARS_IN_IPV6	39

/* Globals. */
int	Opt_severity = DEFAULT_SEVERITY;
int	pcap_off;

void
usage(void)
{
	fprintf(stderr, "Usage: tcpkill [-i interface] [-1..9] expression\n");
	exit(1);
}

/*
  XXX - we ought to determine the rate of seqnum consumption and
  predict the correct seqnum to use, instead of brute force. i suk.
*/
void
pcap_cb(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	char src_host[MAX_CHARS_IN_IPV6 + 1] = {0};
	char dst_host[MAX_CHARS_IN_IPV6 + 1] = {0};
	struct libnet_ipv6_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	unsigned int tcp_hdr_len;
	unsigned int data_len;
	u_short sport, dport;
	u_int32_t seq, ack;
	u_short win;
	libnet_t *l;
	int i;

	l = (libnet_t *)user;

	ip = (struct libnet_ipv6_hdr *)(pkt + pcap_off);
	if (ip->ip_nh != IPPROTO_TCP)
		return;

	tcp = (struct libnet_tcp_hdr *)((u_char*)ip + LIBNET_IPV6_H);
	if (tcp->th_flags & (TH_SYN|TH_FIN|TH_RST))
		return;

	libnet_addr2name6_r(ip->ip_src, LIBNET_DONT_RESOLVE,
			    src_host, MAX_CHARS_IN_IPV6);
	libnet_addr2name6_r(ip->ip_dst, LIBNET_DONT_RESOLVE,
			    dst_host, MAX_CHARS_IN_IPV6);

	tcp_hdr_len = tcp->th_off * 4;
	data_len = ntohs(ip->ip_len) - tcp_hdr_len;

	seq = ntohl(tcp->th_seq);
	ack = ntohl(tcp->th_ack);
	win = ntohs(tcp->th_win);
	sport = ntohs(tcp->th_sport);
	dport = ntohs(tcp->th_dport);

	fprintf(stdout, "%s:%d > %s:%d seq %u:%u, ack %u, win %hu, length %u\n",
		src_host, sport, dst_host, dport,
		seq, seq + data_len, ack, win, data_len);

	for (i = 0; i < Opt_severity; i++) {
		libnet_clear_packet(l);

		/* Bulid TCP header*/
		libnet_build_tcp(dport,           // src port
				 sport,           // dst port
				 ack + (i * win), // seq number
				 0,               // ack number
				 TH_RST,          // control flags
				 0,               // window size
				 0,               // checksum to be filled by libnet
				 0,               // urgent pointer
				 LIBNET_TCP_H,    // total length
				 NULL,            // payload
				 0,               // payload length
				 l,               // libnet context
				 0);              // ptag

		/* Bulid IP header*/
		libnet_build_ipv6(0,            // tc
				  0,            // flow label
				  LIBNET_TCP_H, // total length,
				  IPPROTO_TCP,  // next header
				  128,          // hop limit
				  ip->ip_dst,   // src IP
				  ip->ip_src,	// dst IP
				  NULL,         // payload
				  0,            // payload length
				  l,            // libnet context
				  0);           // ptag

		if (libnet_write(l) < 0)
			fprintf(stderr, "Write error: %s\n",
				libnet_geterror(l));
	}
}

int
main(int argc, char *argv[])
{
	int c;
	char *p, *intf, *filter, ebuf[PCAP_ERRBUF_SIZE];
	libnet_t* l;
	pcap_t *pd;

	intf = NULL;

	while ((c = getopt(argc, argv, "i:123456789h?V")) != -1) {
		switch (c) {
		case 'i':
			intf = optarg;
			break;
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			p = argv[optind - 1];
			if (p[0] == '-' && p[1] == c && p[2] == '\0')
				Opt_severity = atoi(++p);
			else
				Opt_severity = atoi(argv[optind] + 1);
			break;
		default:
			usage();
			break;
		}
	}
	if (intf == NULL && (intf = pcap_lookupdev(ebuf)) == NULL)
		errx(1, "%s", ebuf);

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	filter = copy_argv(argv);

	if ((pd = pcap_init(intf, filter, 128)) == NULL)
		errx(1, "couldn't initialize sniffing");

	if ((pcap_off = pcap_dloff(pd)) < 0)
		errx(1, "couldn't determine link layer offset");

	if ((l = libnet_init(LIBNET_RAW6, NULL, ebuf)) == NULL)
		errx(1, "couldn't initialize libnet");

	warnx("listening on %s [%s]", intf, filter);

	pcap_loop(pd, -1, pcap_cb, (u_char *)l);

	/* NOTREACHED */

	exit(0);
}
