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

#यदि_अपरिभाषितम् _ADDR_H
#परिभाषय _ADDR_H

#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <netinet/in.h>

संरचना xaddr {
	sa_family_t	af;
	सङ्घ {
		संरचना in_addr		v4;
		संरचना in6_addr		v6;
		uint8_t			addr8[16];
		uint16_t		addr16[8];
		uint32_t		addr32[4];
	} xa;		    /* 128-bit address */
	uint32_t	scope_id;	/* iface scope id for v6 */
#परिभाषय v4	xa.v4
#परिभाषय v6	xa.v6
#परिभाषय addr8	xa.addr8
#परिभाषय addr16	xa.addr16
#परिभाषय addr32	xa.addr32
};

पूर्णाङ्क addr_sa_गन्तव्यम्_xaddr(संरचना sockaddr *sa, socklen_t slen, संरचना xaddr *xa);
पूर्णाङ्क addr_netmask(पूर्णाङ्क af, u_int l, संरचना xaddr *n);
पूर्णाङ्क addr_pton(ध्रुव वर्ण *p, संरचना xaddr *n);
पूर्णाङ्क addr_pton_cidr(ध्रुव वर्ण *p, संरचना xaddr *n, u_int *l);
पूर्णाङ्क addr_ntop(ध्रुव संरचना xaddr *n, वर्ण *p, आकार_t len);
पूर्णाङ्क addr_and(संरचना xaddr *dst, ध्रुव संरचना xaddr *a, ध्रुव संरचना xaddr *b);
पूर्णाङ्क addr_cmp(ध्रुव संरचना xaddr *a, ध्रुव संरचना xaddr *b);
पूर्णाङ्क addr_host_गन्तव्यम्_all1s(संरचना xaddr *a, u_int masklen);
पूर्णाङ्क addr_netmatch(ध्रुव संरचना xaddr *host, ध्रुव संरचना xaddr *net,
    u_int masklen);
शून्य addr_increment(संरचना xaddr *a);
#यदि_अन्तः /* _ADDR_H */
