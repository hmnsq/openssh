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

#अगर_अघोषित _ADDR_H
#घोषणा _ADDR_H

#समावेश <sys/socket.h>
#समावेश <netinet/in.h>

काष्ठा xaddr {
	sa_family_t	af;
	जोड़ {
		काष्ठा in_addr		v4;
		काष्ठा in6_addr		v6;
		uint8_t			addr8[16];
		uint16_t		addr16[8];
		uint32_t		addr32[4];
	} xa;		    /* 128-bit address */
	uint32_t	scope_id;	/* iface scope id for v6 */
#घोषणा v4	xa.v4
#घोषणा v6	xa.v6
#घोषणा addr8	xa.addr8
#घोषणा addr16	xa.addr16
#घोषणा addr32	xa.addr32
};

पूर्णांक addr_sa_to_xaddr(काष्ठा sockaddr *sa, socklen_t slen, काष्ठा xaddr *xa);
पूर्णांक addr_netmask(पूर्णांक af, u_int l, काष्ठा xaddr *n);
पूर्णांक addr_pton(स्थिर अक्षर *p, काष्ठा xaddr *n);
पूर्णांक addr_pton_cidr(स्थिर अक्षर *p, काष्ठा xaddr *n, u_int *l);
पूर्णांक addr_ntop(स्थिर काष्ठा xaddr *n, अक्षर *p, माप_प्रकार len);
पूर्णांक addr_and(काष्ठा xaddr *dst, स्थिर काष्ठा xaddr *a, स्थिर काष्ठा xaddr *b);
पूर्णांक addr_cmp(स्थिर काष्ठा xaddr *a, स्थिर काष्ठा xaddr *b);
पूर्णांक addr_host_to_all1s(काष्ठा xaddr *a, u_int masklen);
पूर्णांक addr_netmatch(स्थिर काष्ठा xaddr *host, स्थिर काष्ठा xaddr *net,
    u_int masklen);
व्योम addr_increment(काष्ठा xaddr *a);
#पूर्ण_अगर /* _ADDR_H */
