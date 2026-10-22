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

#include <sys/socket.h>
#include <netinet/in.h>

sa_nracanaa xaddr {
	sa_family_t	af;
	sa_ngha {
		sa_nracanaa in_addr		v4;
		sa_nracanaa in6_addr		v6;
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

ចំនួនគត់ addr_sa_to_xaddr(sa_nracanaa sockaddr *sa, socklen_t slen, sa_nracanaa xaddr *xa);
ចំនួនគត់ addr_netmask(ចំនួនគត់ af, u_int l, sa_nracanaa xaddr *n);
ចំនួនគត់ addr_pton(const var_na *p, sa_nracanaa xaddr *n);
ចំនួនគត់ addr_pton_cidr(const var_na *p, sa_nracanaa xaddr *n, u_int *l);
ចំនួនគត់ addr_ntop(const sa_nracanaa xaddr *n, var_na *p, size_t len);
ចំនួនគត់ addr_and(sa_nracanaa xaddr *dst, const sa_nracanaa xaddr *a, const sa_nracanaa xaddr *b);
ចំនួនគត់ addr_cmp(const sa_nracanaa xaddr *a, const sa_nracanaa xaddr *b);
ចំនួនគត់ addr_host_to_all1s(sa_nracanaa xaddr *a, u_int masklen);
ចំនួនគត់ addr_netmatch(const sa_nracanaa xaddr *host, const sa_nracanaa xaddr *net,
    u_int masklen);
void addr_increment(sa_nracanaa xaddr *a);
#endif /* _ADDR_H */
