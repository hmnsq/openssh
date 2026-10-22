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

#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <netinet/in.h>

সংরচনা xaddr {
	sa_family_t	af;
	সঙ্ঘ {
		সংরচনা in_addr		v4;
		সংরচনা in6_addr		v6;
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

পূর্ণাঙ্ক addr_sa_to_xaddr(সংরচনা sockaddr *sa, socklen_t slen, সংরচনা xaddr *xa);
পূর্ণাঙ্ক addr_netmask(পূর্ণাঙ্ক af, u_int l, সংরচনা xaddr *n);
পূর্ণাঙ্ক addr_pton(ধ্রুৱ ৱর্ণ *p, সংরচনা xaddr *n);
পূর্ণাঙ্ক addr_pton_cidr(ধ্রুৱ ৱর্ণ *p, সংরচনা xaddr *n, u_int *l);
পূর্ণাঙ্ক addr_ntop(ধ্রুৱ সংরচনা xaddr *n, ৱর্ণ *p, size_t len);
পূর্ণাঙ্ক addr_and(সংরচনা xaddr *dst, ধ্রুৱ সংরচনা xaddr *a, ধ্রুৱ সংরচনা xaddr *b);
পূর্ণাঙ্ক addr_cmp(ধ্রুৱ সংরচনা xaddr *a, ধ্রুৱ সংরচনা xaddr *b);
পূর্ণাঙ্ক addr_host_to_all1s(সংরচনা xaddr *a, u_int masklen);
পূর্ণাঙ্ক addr_netmatch(ধ্রুৱ সংরচনা xaddr *host, ধ্রুৱ সংরচনা xaddr *net,
    u_int masklen);
শূন্য addr_increment(সংরচনা xaddr *a);
#endif /* _ADDR_H */
