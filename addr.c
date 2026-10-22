/* $OpenBSD: addr.c,v 1.10 2026/03/03 09:57:25 dtucker Exp $ */

/*
 * Copyright (c) 2004-2008 Damien Miller <djm@mindrot.org>
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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>

#समावेश <netdb.h>
#समावेश <string.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <limits.h>

#समावेश "addr.h"

#घोषणा _SA(x)	((काष्ठा sockaddr *)(x))

अटल पूर्णांक
addr_unicast_masklen(पूर्णांक af)
{
	चयन (af) {
	हाल AF_INET:
		वापस 32;
	हाल AF_INET6:
		वापस 128;
	शेष:
		वापस -1;
	}
}

अटल अंतरभूत पूर्णांक
masklen_valid(पूर्णांक af, u_int masklen)
{
	चयन (af) {
	हाल AF_INET:
		वापस masklen <= 32 ? 0 : -1;
	हाल AF_INET6:
		वापस masklen <= 128 ? 0 : -1;
	शेष:
		वापस -1;
	}
}

अटल पूर्णांक
addr_xaddr_to_sa(स्थिर काष्ठा xaddr *xa, काष्ठा sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	काष्ठा sockaddr_in *in4 = (काष्ठा sockaddr_in *)sa;
	काष्ठा sockaddr_in6 *in6 = (काष्ठा sockaddr_in6 *)sa;

	अगर (xa == शून्य || sa == शून्य || len == शून्य)
		वापस -1;

	चयन (xa->af) {
	हाल AF_INET:
		अगर (*len < माप(*in4))
			वापस -1;
		स_रखो(sa, '\0', माप(*in4));
		*len = माप(*in4);
#अगर_घोषित SOCK_HAS_LEN
		in4->sin_len = माप(*in4);
#पूर्ण_अगर
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		स_नकल(&in4->sin_addr, &xa->v4, माप(in4->sin_addr));
		अवरोध;
	हाल AF_INET6:
		अगर (*len < माप(*in6))
			वापस -1;
		स_रखो(sa, '\0', माप(*in6));
		*len = माप(*in6);
#अगर_घोषित SOCK_HAS_LEN
		in6->sin6_len = माप(*in6);
#पूर्ण_अगर
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		स_नकल(&in6->sin6_addr, &xa->v6, माप(in6->sin6_addr));
#अगर_घोषित HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#पूर्ण_अगर
		अवरोध;
	शेष:
		वापस -1;
	}
	वापस 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
पूर्णांक
addr_sa_to_xaddr(काष्ठा sockaddr *sa, socklen_t slen, काष्ठा xaddr *xa)
{
	काष्ठा sockaddr_in *in4 = (काष्ठा sockaddr_in *)sa;
	काष्ठा sockaddr_in6 *in6 = (काष्ठा sockaddr_in6 *)sa;

	स_रखो(xa, '\0', माप(*xa));

	चयन (sa->sa_family) {
	हाल AF_INET:
		अगर (slen < (socklen_t)माप(*in4))
			वापस -1;
		xa->af = AF_INET;
		स_नकल(&xa->v4, &in4->sin_addr, माप(xa->v4));
		अवरोध;
	हाल AF_INET6:
		अगर (slen < (socklen_t)माप(*in6))
			वापस -1;
		xa->af = AF_INET6;
		स_नकल(&xa->v6, &in6->sin6_addr, माप(xa->v6));
#अगर_घोषित HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#पूर्ण_अगर
		अवरोध;
	शेष:
		वापस -1;
	}

	वापस 0;
}

अटल पूर्णांक
addr_invert(काष्ठा xaddr *n)
{
	पूर्णांक i;

	अगर (n == शून्य)
		वापस -1;

	चयन (n->af) {
	हाल AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		वापस 0;
	हाल AF_INET6:
		क्रम (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		वापस 0;
	शेष:
		वापस -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
पूर्णांक
addr_netmask(पूर्णांक af, u_int l, काष्ठा xaddr *n)
{
	पूर्णांक i;

	अगर (masklen_valid(af, l) != 0 || n == शून्य)
		वापस -1;

	स_रखो(n, '\0', माप(*n));
	चयन (af) {
	हाल AF_INET:
		n->af = AF_INET;
		अगर (l == 0)
			वापस 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		वापस 0;
	हाल AF_INET6:
		n->af = AF_INET6;
		क्रम (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		अगर (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		वापस 0;
	शेष:
		वापस -1;
	}
}

अटल पूर्णांक
addr_hostmask(पूर्णांक af, u_int l, काष्ठा xaddr *n)
{
	अगर (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		वापस -1;
	वापस 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
पूर्णांक
addr_and(काष्ठा xaddr *dst, स्थिर काष्ठा xaddr *a, स्थिर काष्ठा xaddr *b)
{
	पूर्णांक i;

	अगर (dst == शून्य || a == शून्य || b == शून्य || a->af != b->af)
		वापस -1;

	स_नकल(dst, a, माप(*dst));
	चयन (a->af) {
	हाल AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		वापस 0;
	हाल AF_INET6:
		dst->scope_id = a->scope_id;
		क्रम (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		वापस 0;
	शेष:
		वापस -1;
	}
}

अटल पूर्णांक
addr_or(काष्ठा xaddr *dst, स्थिर काष्ठा xaddr *a, स्थिर काष्ठा xaddr *b)
{
	पूर्णांक i;

	अगर (dst == शून्य || a == शून्य || b == शून्य || a->af != b->af)
		वापस (-1);

	स_नकल(dst, a, माप(*dst));
	चयन (a->af) {
	हाल AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		वापस (0);
	हाल AF_INET6:
		क्रम (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		वापस (0);
	शेष:
		वापस (-1);
	}
}

पूर्णांक
addr_cmp(स्थिर काष्ठा xaddr *a, स्थिर काष्ठा xaddr *b)
{
	पूर्णांक i;

	अगर (a->af != b->af)
		वापस (a->af == AF_INET6 ? 1 : -1);

	चयन (a->af) {
	हाल AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		अगर (a->v4.s_addr == b->v4.s_addr)
			वापस 0;
		वापस (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	हाल AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		क्रम (i = 0; i < 16; i++)
			अगर (a->addr8[i] - b->addr8[i] != 0)
				वापस (a->addr8[i] - b->addr8[i]);
		अगर (a->scope_id == b->scope_id)
			वापस (0);
		वापस (a->scope_id > b->scope_id ? 1 : -1);
	शेष:
		वापस (-1);
	}
}

अटल पूर्णांक
addr_is_all0s(स्थिर काष्ठा xaddr *a)
{
	पूर्णांक i;

	चयन (a->af) {
	हाल AF_INET:
		वापस (a->v4.s_addr == 0 ? 0 : -1);
	हाल AF_INET6:
		क्रम (i = 0; i < 4; i++)
			अगर (a->addr32[i] != 0)
				वापस -1;
		वापस 0;
	शेष:
		वापस -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
व्योम
addr_increment(काष्ठा xaddr *a)
{
	पूर्णांक i;
	uint32_t n;

	चयन (a->af) {
	हाल AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		अवरोध;
	हाल AF_INET6:
		क्रम (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			अगर (n != 0)
				अवरोध;
		}
		अवरोध;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
अटल पूर्णांक
addr_host_is_all0s(स्थिर काष्ठा xaddr *a, u_int masklen)
{
	काष्ठा xaddr tmp_addr, tmp_mask, tmp_परिणाम;

	स_नकल(&tmp_addr, a, माप(tmp_addr));
	अगर (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		वापस -1;
	अगर (addr_and(&tmp_परिणाम, &tmp_addr, &tmp_mask) == -1)
		वापस -1;
	वापस addr_is_all0s(&tmp_परिणाम);
}

#अगर 0
अटल पूर्णांक
addr_host_to_all0s(काष्ठा xaddr *a, u_int masklen)
{
	काष्ठा xaddr tmp_mask;

	अगर (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		वापस (-1);
	अगर (addr_and(a, a, &tmp_mask) == -1)
		वापस (-1);
	वापस (0);
}
#पूर्ण_अगर

पूर्णांक
addr_host_to_all1s(काष्ठा xaddr *a, u_int masklen)
{
	काष्ठा xaddr tmp_mask;

	अगर (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		वापस (-1);
	अगर (addr_or(a, a, &tmp_mask) == -1)
		वापस (-1);
	वापस (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
पूर्णांक
addr_pton(स्थिर अक्षर *p, काष्ठा xaddr *n)
{
	काष्ठा addrinfo hints, *ai;

	स_रखो(&hints, '\0', माप(hints));
	hints.ai_flags = AI_NUMERICHOST;

	अगर (p == शून्य || getaddrinfo(p, शून्य, &hints, &ai) != 0)
		वापस -1;

	अगर (ai == शून्य)
		वापस -1;

	अगर (ai->ai_addr == शून्य) {
		freeaddrinfo(ai);
		वापस -1;
	}

	अगर (n != शून्य && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		वापस -1;
	}

	freeaddrinfo(ai);
	वापस 0;
}

#अगर 0
अटल पूर्णांक
addr_sa_pton(स्थिर अक्षर *h, स्थिर अक्षर *s, काष्ठा sockaddr *sa, socklen_t slen)
{
	काष्ठा addrinfo hints, *ai;

	स_रखो(&hints, '\0', माप(hints));
	hints.ai_flags = AI_NUMERICHOST;

	अगर (h == शून्य || getaddrinfo(h, s, &hints, &ai) != 0)
		वापस -1;

	अगर (ai == शून्य)
		वापस -1;

	अगर (ai->ai_addr == शून्य) {
		freeaddrinfo(ai);
		वापस -1;
	}

	अगर (sa != शून्य) {
		अगर (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			वापस -1;
		}
		स_नकल(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	वापस 0;
}
#पूर्ण_अगर

पूर्णांक
addr_ntop(स्थिर काष्ठा xaddr *n, अक्षर *p, माप_प्रकार len)
{
	काष्ठा sockaddr_storage ss;
	socklen_t slen = माप(ss);

	अगर (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		वापस -1;
	अगर (p == शून्य || len == 0)
		वापस -1;
	अगर (getnameinfo(_SA(&ss), slen, p, len, शून्य, 0,
	    NI_NUMERICHOST) != 0)
		वापस -1;

	वापस 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
पूर्णांक
addr_pton_cidr(स्थिर अक्षर *p, काष्ठा xaddr *n, u_int *l)
{
	काष्ठा xaddr tmp;
	u_int masklen = 999;
	अक्षर addrbuf[64], *mp;
	स्थिर अक्षर *errstr;

	/* Don't modify argument */
	अगर (p == शून्य || strlcpy(addrbuf, p, माप(addrbuf)) >= माप(addrbuf))
		वापस -1;

	अगर ((mp = म_अक्षर(addrbuf, '/')) != शून्य) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, पूर्णांक_उच्च, &errstr);
		अगर (errstr)
			वापस -1;
	}

	अगर (addr_pton(addrbuf, &tmp) == -1)
		वापस -1;

	अगर (mp == शून्य)
		masklen = addr_unicast_masklen(tmp.af);
	अगर (masklen_valid(tmp.af, masklen) == -1)
		वापस -2;
	अगर (addr_host_is_all0s(&tmp, masklen) != 0)
		वापस -2;

	अगर (n != शून्य)
		स_नकल(n, &tmp, माप(*n));
	अगर (l != शून्य)
		*l = masklen;

	वापस 0;
}

पूर्णांक
addr_netmatch(स्थिर काष्ठा xaddr *host, स्थिर काष्ठा xaddr *net, u_int masklen)
{
	काष्ठा xaddr tmp_mask, tmp_परिणाम;

	अगर (host->af != net->af)
		वापस -1;

	अगर (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		वापस -1;
	अगर (addr_and(&tmp_परिणाम, host, &tmp_mask) == -1)
		वापस -1;
	वापस addr_cmp(&tmp_परिणाम, net);
}
