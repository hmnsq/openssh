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

#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <netinet/in.h>

கட்டமைப்பு xaddr {
	sa_family_t	af;
	ஒன்றிப்பு {
		கட்டமைப்பு in_addr		v4;
		கட்டமைப்பு in6_addr		v6;
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

முழு addr_sa_to_xaddr(கட்டமைப்பு sockaddr *sa, socklen_t slen, கட்டமைப்பு xaddr *xa);
முழு addr_netmask(முழு af, u_int l, கட்டமைப்பு xaddr *n);
முழு addr_pton(மாறிலி எழுத்து *p, கட்டமைப்பு xaddr *n);
முழு addr_pton_cidr(மாறிலி எழுத்து *p, கட்டமைப்பு xaddr *n, u_int *l);
முழு addr_ntop(மாறிலி கட்டமைப்பு xaddr *n, எழுத்து *p, size_t len);
முழு addr_and(கட்டமைப்பு xaddr *dst, மாறிலி கட்டமைப்பு xaddr *a, மாறிலி கட்டமைப்பு xaddr *b);
முழு addr_cmp(மாறிலி கட்டமைப்பு xaddr *a, மாறிலி கட்டமைப்பு xaddr *b);
முழு addr_host_to_all1s(கட்டமைப்பு xaddr *a, u_int masklen);
முழு addr_netmatch(மாறிலி கட்டமைப்பு xaddr *host, மாறிலி கட்டமைப்பு xaddr *net,
    u_int masklen);
வெறுமை addr_increment(கட்டமைப்பு xaddr *a);
#endif /* _ADDR_H */
