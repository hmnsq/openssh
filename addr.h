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

#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <netinet/in.h>

কাঠামো xaddr {
	sa_family_t	af;
	সংঘ {
		কাঠামো in_addr		v4;
		কাঠামো in6_addr		v6;
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

পূর্ণসংখ্যা addr_sa_to_xaddr(কাঠামো sockaddr *sa, socklen_t slen, কাঠামো xaddr *xa);
পূর্ণসংখ্যা addr_netmask(পূর্ণসংখ্যা af, u_int l, কাঠামো xaddr *n);
পূর্ণসংখ্যা addr_pton(ধ্রুবক অক্ষর *p, কাঠামো xaddr *n);
পূর্ণসংখ্যা addr_pton_cidr(ধ্রুবক অক্ষর *p, কাঠামো xaddr *n, u_int *l);
পূর্ণসংখ্যা addr_ntop(ধ্রুবক কাঠামো xaddr *n, অক্ষর *p, আকার_t len);
পূর্ণসংখ্যা addr_and(কাঠামো xaddr *dst, ধ্রুবক কাঠামো xaddr *a, ধ্রুবক কাঠামো xaddr *b);
পূর্ণসংখ্যা addr_cmp(ধ্রুবক কাঠামো xaddr *a, ধ্রুবক কাঠামো xaddr *b);
পূর্ণসংখ্যা addr_host_to_all1s(কাঠামো xaddr *a, u_int masklen);
পূর্ণসংখ্যা addr_netmatch(ধ্রুবক কাঠামো xaddr *host, ধ্রুবক কাঠামো xaddr *net,
    u_int masklen);
শূন্য addr_increment(কাঠামো xaddr *a);
#endif /* _ADDR_H */
