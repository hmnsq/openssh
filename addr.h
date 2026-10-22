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

#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <netinet/in.h>

ഘടന xaddr {
	sa_family_t	af;
	സംഘം {
		ഘടന in_addr		v4;
		ഘടന in6_addr		v6;
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

പൂർണ്ണസംഖ്യ addr_sa_to_xaddr(ഘടന sockaddr *sa, socklen_t slen, ഘടന xaddr *xa);
പൂർണ്ണസംഖ്യ addr_netmask(പൂർണ്ണസംഖ്യ af, u_int l, ഘടന xaddr *n);
പൂർണ്ണസംഖ്യ addr_pton(സ്ഥിരം അക്ഷരം *p, ഘടന xaddr *n);
പൂർണ്ണസംഖ്യ addr_pton_cidr(സ്ഥിരം അക്ഷരം *p, ഘടന xaddr *n, u_int *l);
പൂർണ്ണസംഖ്യ addr_ntop(സ്ഥിരം ഘടന xaddr *n, അക്ഷരം *p, size_t len);
പൂർണ്ണസംഖ്യ addr_and(ഘടന xaddr *dst, സ്ഥിരം ഘടന xaddr *a, സ്ഥിരം ഘടന xaddr *b);
പൂർണ്ണസംഖ്യ addr_cmp(സ്ഥിരം ഘടന xaddr *a, സ്ഥിരം ഘടന xaddr *b);
പൂർണ്ണസംഖ്യ addr_host_to_all1s(ഘടന xaddr *a, u_int masklen);
പൂർണ്ണസംഖ്യ addr_netmatch(സ്ഥിരം ഘടന xaddr *host, സ്ഥിരം ഘടന xaddr *net,
    u_int masklen);
ശൂന്യം addr_increment(ഘടന xaddr *a);
#endif /* _ADDR_H */
