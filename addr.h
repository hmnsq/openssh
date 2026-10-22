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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _ADDR_H
#ವ್ಯಾಖ್ಯಾನಿಸು _ADDR_H

#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>

ರಚನೆ xaddr {
	sa_family_t	af;
	ಒಕ್ಕೂಟ {
		ರಚನೆ in_addr		v4;
		ರಚನೆ in6_addr		v6;
		uint8_t			addr8[16];
		uint16_t		addr16[8];
		uint32_t		addr32[4];
	} xa;		    /* 128-bit address */
	uint32_t	scope_id;	/* iface scope id for v6 */
#ವ್ಯಾಖ್ಯಾನಿಸು v4	xa.v4
#ವ್ಯಾಖ್ಯಾನಿಸು v6	xa.v6
#ವ್ಯಾಖ್ಯಾನಿಸು addr8	xa.addr8
#ವ್ಯಾಖ್ಯಾನಿಸು addr16	xa.addr16
#ವ್ಯಾಖ್ಯಾನಿಸು addr32	xa.addr32
};

ಪೂರ್ಣಾಂಕ addr_sa_ಗಮ್ಯ_xaddr(ರಚನೆ sockaddr *sa, socklen_t slen, ರಚನೆ xaddr *xa);
ಪೂರ್ಣಾಂಕ addr_netmask(ಪೂರ್ಣಾಂಕ af, u_int l, ರಚನೆ xaddr *n);
ಪೂರ್ಣಾಂಕ addr_pton(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p, ರಚನೆ xaddr *n);
ಪೂರ್ಣಾಂಕ addr_pton_cidr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p, ರಚನೆ xaddr *n, u_int *l);
ಪೂರ್ಣಾಂಕ addr_ntop(ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *n, ಅಕ್ಷರ *p, ಗಾತ್ರ_t len);
ಪೂರ್ಣಾಂಕ addr_and(ರಚನೆ xaddr *dst, ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *a, ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *b);
ಪೂರ್ಣಾಂಕ addr_cmp(ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *a, ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *b);
ಪೂರ್ಣಾಂಕ addr_host_ಗಮ್ಯ_all1s(ರಚನೆ xaddr *a, u_int masklen);
ಪೂರ್ಣಾಂಕ addr_netmatch(ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *host, ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *net,
    u_int masklen);
ಶೂನ್ಯ addr_increment(ರಚನೆ xaddr *a);
#ಆದರೆ_ಅಂತ್ಯ /* _ADDR_H */
