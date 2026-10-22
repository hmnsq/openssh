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

#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <netinet/in.h>

ସଂରଚନା xaddr {
	sa_family_t	af;
	ସଂଘ {
		ସଂରଚନା in_addr		v4;
		ସଂରଚନା in6_addr		v6;
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

ପୂର୍ଣ୍ଣସଂଖ୍ୟା addr_sa_to_xaddr(ସଂରଚନା sockaddr *sa, socklen_t slen, ସଂରଚନା xaddr *xa);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା addr_netmask(ପୂର୍ଣ୍ଣସଂଖ୍ୟା af, u_int l, ସଂରଚନା xaddr *n);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା addr_pton(ଅଚଳ ଅକ୍ଷର *p, ସଂରଚନା xaddr *n);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା addr_pton_cidr(ଅଚଳ ଅକ୍ଷର *p, ସଂରଚନା xaddr *n, u_int *l);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା addr_ntop(ଅଚଳ ସଂରଚନା xaddr *n, ଅକ୍ଷର *p, size_t len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା addr_and(ସଂରଚନା xaddr *dst, ଅଚଳ ସଂରଚନା xaddr *a, ଅଚଳ ସଂରଚନା xaddr *b);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା addr_cmp(ଅଚଳ ସଂରଚନା xaddr *a, ଅଚଳ ସଂରଚନା xaddr *b);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା addr_host_to_all1s(ସଂରଚନା xaddr *a, u_int masklen);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା addr_netmatch(ଅଚଳ ସଂରଚନା xaddr *host, ଅଚଳ ସଂରଚନା xaddr *net,
    u_int masklen);
ଶୂନ୍ୟ addr_increment(ସଂରଚନା xaddr *a);
#endif /* _ADDR_H */
