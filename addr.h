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

#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>

ಸಂರಚನಾ xaddr {
	sa_family_t	af;
	ಸಙ್ಘ {
		ಸಂರಚನಾ in_addr		v4;
		ಸಂರಚನಾ in6_addr		v6;
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

ಪೂರ್ಣಾಙ್ಕ addr_sa_to_xaddr(ಸಂರಚನಾ sockaddr *sa, socklen_t slen, ಸಂರಚನಾ xaddr *xa);
ಪೂರ್ಣಾಙ್ಕ addr_netmask(ಪೂರ್ಣಾಙ್ಕ af, u_int l, ಸಂರಚನಾ xaddr *n);
ಪೂರ್ಣಾಙ್ಕ addr_pton(ಧ್ರುವ ವರ್ಣ *p, ಸಂರಚನಾ xaddr *n);
ಪೂರ್ಣಾಙ್ಕ addr_pton_cidr(ಧ್ರುವ ವರ್ಣ *p, ಸಂರಚನಾ xaddr *n, u_int *l);
ಪೂರ್ಣಾಙ್ಕ addr_ntop(ಧ್ರುವ ಸಂರಚನಾ xaddr *n, ವರ್ಣ *p, size_t len);
ಪೂರ್ಣಾಙ್ಕ addr_and(ಸಂರಚನಾ xaddr *dst, ಧ್ರುವ ಸಂರಚನಾ xaddr *a, ಧ್ರುವ ಸಂರಚನಾ xaddr *b);
ಪೂರ್ಣಾಙ್ಕ addr_cmp(ಧ್ರುವ ಸಂರಚನಾ xaddr *a, ಧ್ರುವ ಸಂರಚನಾ xaddr *b);
ಪೂರ್ಣಾಙ್ಕ addr_host_to_all1s(ಸಂರಚನಾ xaddr *a, u_int masklen);
ಪೂರ್ಣಾಙ್ಕ addr_netmatch(ಧ್ರುವ ಸಂರಚನಾ xaddr *host, ಧ್ರುವ ಸಂರಚನಾ xaddr *net,
    u_int masklen);
ಶೂನ್ಯ addr_increment(ಸಂರಚನಾ xaddr *a);
#endif /* _ADDR_H */
