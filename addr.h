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

#నిర్వచితం_కాకపోతే _ADDR_H
#నిర్వచించు _ADDR_H

#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <netinet/in.h>

నిర్మాణం xaddr {
	sa_family_t	af;
	సంఘం {
		నిర్మాణం in_addr		v4;
		నిర్మాణం in6_addr		v6;
		uint8_t			addr8[16];
		uint16_t		addr16[8];
		uint32_t		addr32[4];
	} xa;		    /* 128-bit address */
	uint32_t	scope_id;	/* iface scope id for v6 */
#నిర్వచించు v4	xa.v4
#నిర్వచించు v6	xa.v6
#నిర్వచించు addr8	xa.addr8
#నిర్వచించు addr16	xa.addr16
#నిర్వచించు addr32	xa.addr32
};

పూర్ణాంకం addr_sa_గమ్యం_xaddr(నిర్మాణం sockaddr *sa, socklen_t slen, నిర్మాణం xaddr *xa);
పూర్ణాంకం addr_netmask(పూర్ణాంకం af, u_int l, నిర్మాణం xaddr *n);
పూర్ణాంకం addr_pton(స్థిరరాశి అక్షరం *p, నిర్మాణం xaddr *n);
పూర్ణాంకం addr_pton_cidr(స్థిరరాశి అక్షరం *p, నిర్మాణం xaddr *n, u_int *l);
పూర్ణాంకం addr_ntop(స్థిరరాశి నిర్మాణం xaddr *n, అక్షరం *p, కొలత_t len);
పూర్ణాంకం addr_and(నిర్మాణం xaddr *dst, స్థిరరాశి నిర్మాణం xaddr *a, స్థిరరాశి నిర్మాణం xaddr *b);
పూర్ణాంకం addr_cmp(స్థిరరాశి నిర్మాణం xaddr *a, స్థిరరాశి నిర్మాణం xaddr *b);
పూర్ణాంకం addr_host_గమ్యం_all1s(నిర్మాణం xaddr *a, u_int masklen);
పూర్ణాంకం addr_netmatch(స్థిరరాశి నిర్మాణం xaddr *host, స్థిరరాశి నిర్మాణం xaddr *net,
    u_int masklen);
శూన్య addr_increment(నిర్మాణం xaddr *a);
#అయితే_ముగింపు /* _ADDR_H */
