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

#شامل <sys/socket.h>
#شامل <netinet/in.h>

ساختار xaddr {
	sa_family_t	af;
	اجتماع {
		ساختار in_addr		v4;
		ساختار in6_addr		v6;
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

صحیح addr_sa_to_xaddr(ساختار sockaddr *sa, socklen_t slen, ساختار xaddr *xa);
صحیح addr_netmask(صحیح af, u_int l, ساختار xaddr *n);
صحیح addr_pton(ثابت نویسه *p, ساختار xaddr *n);
صحیح addr_pton_cidr(ثابت نویسه *p, ساختار xaddr *n, u_int *l);
صحیح addr_ntop(ثابت ساختار xaddr *n, نویسه *p, size_t len);
صحیح addr_and(ساختار xaddr *dst, ثابت ساختار xaddr *a, ثابت ساختار xaddr *b);
صحیح addr_cmp(ثابت ساختار xaddr *a, ثابت ساختار xaddr *b);
صحیح addr_host_to_all1s(ساختار xaddr *a, u_int masklen);
صحیح addr_netmatch(ثابت ساختار xaddr *host, ثابت ساختار xaddr *net,
    u_int masklen);
تهی addr_increment(ساختار xaddr *a);
#endif /* _ADDR_H */
