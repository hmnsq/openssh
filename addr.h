/*
 * Copyright (c) 2004,2005 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Address handling routines */

#ifndef _ADDR_H
#define _ADDR_H

#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <netinet/in.h>

સંરચના xaddr {
	sa_family_t	af;
	સંઘ {
		સંરચના in_addr		v4;
		સંરચના in6_addr		v6;
		uint8_t			addr8[16];
		uint16_t		addr16[8];
		uint32_t		addr32[4];
	} xa;		    /* 128-bit address */
	uint32_t	scope_id;	/* iface scope id for v6 */
#define v4	xa.v4
#define v6	xa.v6
#define addr8	xa.addr8
#define addr16	xa.addr16
#define addr32	xa.addr32
};

પૂર્ણાંક addr_sa_to_xaddr(સંરચના sockaddr *sa, socklen_t slen, સંરચના xaddr *xa);
પૂર્ણાંક addr_netmask(પૂર્ણાંક af, u_int l, સંરચના xaddr *n);
પૂર્ણાંક addr_pton(અચલ અક્ષર *p, સંરચના xaddr *n);
પૂર્ણાંક addr_pton_cidr(અચલ અક્ષર *p, સંરચના xaddr *n, u_int *l);
પૂર્ણાંક addr_ntop(અચલ સંરચના xaddr *n, અક્ષર *p, size_t len);
પૂર્ણાંક addr_and(સંરચના xaddr *dst, અચલ સંરચના xaddr *a, અચલ સંરચના xaddr *b);
પૂર્ણાંક addr_cmp(અચલ સંરચના xaddr *a, અચલ સંરચના xaddr *b);
પૂર્ણાંક addr_host_to_all1s(સંરચના xaddr *a, u_int masklen);
પૂર્ણાંક addr_netmatch(અચલ સંરચના xaddr *host, અચલ સંરચના xaddr *net,
    u_int masklen);
શૂન્ય addr_increment(સંરચના xaddr *a);
#endif /* _ADDR_H */
