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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _ADDR_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _ADDR_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>

ਬਣਤਰ xaddr {
	sa_family_t	af;
	ਸੰਘ {
		ਬਣਤਰ in_addr		v4;
		ਬਣਤਰ in6_addr		v6;
		uint8_t			addr8[16];
		uint16_t		addr16[8];
		uint32_t		addr32[4];
	} xa;		    /* 128-bit address */
	uint32_t	scope_id;	/* iface scope id for v6 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ v4	xa.v4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ v6	xa.v6
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ addr8	xa.addr8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ addr16	xa.addr16
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ addr32	xa.addr32
};

ਪੂਰਨ addr_sa_ਮੰਜ਼ਿਲ_xaddr(ਬਣਤਰ sockaddr *sa, socklen_t slen, ਬਣਤਰ xaddr *xa);
ਪੂਰਨ addr_netmask(ਪੂਰਨ af, u_int l, ਬਣਤਰ xaddr *n);
ਪੂਰਨ addr_pton(ਅਚਲ ਅੱਖਰ *p, ਬਣਤਰ xaddr *n);
ਪੂਰਨ addr_pton_cidr(ਅਚਲ ਅੱਖਰ *p, ਬਣਤਰ xaddr *n, u_int *l);
ਪੂਰਨ addr_ntop(ਅਚਲ ਬਣਤਰ xaddr *n, ਅੱਖਰ *p, ਮਾਪ_t len);
ਪੂਰਨ addr_and(ਬਣਤਰ xaddr *dst, ਅਚਲ ਬਣਤਰ xaddr *a, ਅਚਲ ਬਣਤਰ xaddr *b);
ਪੂਰਨ addr_cmp(ਅਚਲ ਬਣਤਰ xaddr *a, ਅਚਲ ਬਣਤਰ xaddr *b);
ਪੂਰਨ addr_host_ਮੰਜ਼ਿਲ_all1s(ਬਣਤਰ xaddr *a, u_int masklen);
ਪੂਰਨ addr_netmatch(ਅਚਲ ਬਣਤਰ xaddr *host, ਅਚਲ ਬਣਤਰ xaddr *net,
    u_int masklen);
ਖਾਲੀ addr_increment(ਬਣਤਰ xaddr *a);
#ਜੇ_ਅੰਤ /* _ADDR_H */
