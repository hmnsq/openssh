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

#اگر_غیر_تعریف_شدہ _ADDR_H
#تعریف_کرو _ADDR_H

#شامل <sys/socket.h>
#شامل <netinet/in.h>

ساخت xaddr {
	sa_family_t	af;
	اتحاد {
		ساخت in_addr		v4;
		ساخت in6_addr		v6;
		uint8_t			addr8[16];
		uint16_t		addr16[8];
		uint32_t		addr32[4];
	} xa;		    /* 128-bit address */
	uint32_t	scope_id;	/* iface scope id for v6 */
#تعریف_کرو v4	xa.v4
#تعریف_کرو v6	xa.v6
#تعریف_کرو addr8	xa.addr8
#تعریف_کرو addr16	xa.addr16
#تعریف_کرو addr32	xa.addr32
};

صحیح addr_sa_مقصد_xaddr(ساخت sockaddr *sa, socklen_t slen, ساخت xaddr *xa);
صحیح addr_netmask(صحیح af, u_int l, ساخت xaddr *n);
صحیح addr_pton(ثابت حرف *p, ساخت xaddr *n);
صحیح addr_pton_cidr(ثابت حرف *p, ساخت xaddr *n, u_int *l);
صحیح addr_ntop(ثابت ساخت xaddr *n, حرف *p, سائز_t len);
صحیح addr_and(ساخت xaddr *dst, ثابت ساخت xaddr *a, ثابت ساخت xaddr *b);
صحیح addr_cmp(ثابت ساخت xaddr *a, ثابت ساخت xaddr *b);
صحیح addr_host_مقصد_all1s(ساخت xaddr *a, u_int masklen);
صحیح addr_netmatch(ثابت ساخت xaddr *host, ثابت ساخت xaddr *net,
    u_int masklen);
خالی addr_increment(ساخت xaddr *a);
#اگر_ختم /* _ADDR_H */
