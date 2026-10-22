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

#ضمن <sys/socket.h>
#ضمن <netinet/in.h>

بنية xaddr {
	sa_family_t	af;
	اتحاد {
		بنية in_addr		v4;
		بنية in6_addr		v6;
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

صحيح addr_sa_to_xaddr(بنية sockaddr *sa, socklen_t slen, بنية xaddr *xa);
صحيح addr_netmask(صحيح af, u_int l, بنية xaddr *n);
صحيح addr_pton(ثابت حرف *p, بنية xaddr *n);
صحيح addr_pton_cidr(ثابت حرف *p, بنية xaddr *n, u_int *l);
صحيح addr_ntop(ثابت بنية xaddr *n, حرف *p, size_t len);
صحيح addr_and(بنية xaddr *dst, ثابت بنية xaddr *a, ثابت بنية xaddr *b);
صحيح addr_cmp(ثابت بنية xaddr *a, ثابت بنية xaddr *b);
صحيح addr_host_to_all1s(بنية xaddr *a, u_int masklen);
صحيح addr_netmatch(ثابت بنية xaddr *host, ثابت بنية xaddr *net,
    u_int masklen);
فراغ addr_increment(بنية xaddr *a);
#endif /* _ADDR_H */
