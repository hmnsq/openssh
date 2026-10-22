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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <netdb.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "addr.h"

#define _SA(x)	((संरचना sockaddr *)(x))

स्थिर पूर्णांक
addr_unicast_masklen(पूर्णांक af)
{
	निवड (af) {
	स्थिती AF_INET:
		परत 32;
	स्थिती AF_INET6:
		परत 128;
	पूर्वनिर्धारित:
		परत -1;
	}
}

स्थिर ओळीत पूर्णांक
masklen_valid(पूर्णांक af, u_int masklen)
{
	निवड (af) {
	स्थिती AF_INET:
		परत masklen <= 32 ? 0 : -1;
	स्थिती AF_INET6:
		परत masklen <= 128 ? 0 : -1;
	पूर्वनिर्धारित:
		परत -1;
	}
}

स्थिर पूर्णांक
addr_xaddr_to_sa(स्थिरांक संरचना xaddr *xa, संरचना sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	संरचना sockaddr_in *in4 = (संरचना sockaddr_in *)sa;
	संरचना sockaddr_in6 *in6 = (संरचना sockaddr_in6 *)sa;

	जर (xa == रिक्त || sa == रिक्त || len == रिक्त)
		परत -1;

	निवड (xa->af) {
	स्थिती AF_INET:
		जर (*len < आकार(*in4))
			परत -1;
		स_रखो(sa, '\0', आकार(*in4));
		*len = आकार(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = आकार(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		स_नकल(&in4->sin_addr, &xa->v4, आकार(in4->sin_addr));
		थांबा;
	स्थिती AF_INET6:
		जर (*len < आकार(*in6))
			परत -1;
		स_रखो(sa, '\0', आकार(*in6));
		*len = आकार(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = आकार(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		स_नकल(&in6->sin6_addr, &xa->v6, आकार(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		थांबा;
	पूर्वनिर्धारित:
		परत -1;
	}
	परत 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
पूर्णांक
addr_sa_to_xaddr(संरचना sockaddr *sa, socklen_t slen, संरचना xaddr *xa)
{
	संरचना sockaddr_in *in4 = (संरचना sockaddr_in *)sa;
	संरचना sockaddr_in6 *in6 = (संरचना sockaddr_in6 *)sa;

	स_रखो(xa, '\0', आकार(*xa));

	निवड (sa->sa_family) {
	स्थिती AF_INET:
		जर (slen < (socklen_t)आकार(*in4))
			परत -1;
		xa->af = AF_INET;
		स_नकल(&xa->v4, &in4->sin_addr, आकार(xa->v4));
		थांबा;
	स्थिती AF_INET6:
		जर (slen < (socklen_t)आकार(*in6))
			परत -1;
		xa->af = AF_INET6;
		स_नकल(&xa->v6, &in6->sin6_addr, आकार(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		थांबा;
	पूर्वनिर्धारित:
		परत -1;
	}

	परत 0;
}

स्थिर पूर्णांक
addr_invert(संरचना xaddr *n)
{
	पूर्णांक i;

	जर (n == रिक्त)
		परत -1;

	निवड (n->af) {
	स्थिती AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		परत 0;
	स्थिती AF_INET6:
		साठी (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		परत 0;
	पूर्वनिर्धारित:
		परत -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
पूर्णांक
addr_netmask(पूर्णांक af, u_int l, संरचना xaddr *n)
{
	पूर्णांक i;

	जर (masklen_valid(af, l) != 0 || n == रिक्त)
		परत -1;

	स_रखो(n, '\0', आकार(*n));
	निवड (af) {
	स्थिती AF_INET:
		n->af = AF_INET;
		जर (l == 0)
			परत 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		परत 0;
	स्थिती AF_INET6:
		n->af = AF_INET6;
		साठी (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		जर (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		परत 0;
	पूर्वनिर्धारित:
		परत -1;
	}
}

स्थिर पूर्णांक
addr_hostmask(पूर्णांक af, u_int l, संरचना xaddr *n)
{
	जर (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		परत -1;
	परत 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
पूर्णांक
addr_and(संरचना xaddr *dst, स्थिरांक संरचना xaddr *a, स्थिरांक संरचना xaddr *b)
{
	पूर्णांक i;

	जर (dst == रिक्त || a == रिक्त || b == रिक्त || a->af != b->af)
		परत -1;

	स_नकल(dst, a, आकार(*dst));
	निवड (a->af) {
	स्थिती AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		परत 0;
	स्थिती AF_INET6:
		dst->scope_id = a->scope_id;
		साठी (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		परत 0;
	पूर्वनिर्धारित:
		परत -1;
	}
}

स्थिर पूर्णांक
addr_or(संरचना xaddr *dst, स्थिरांक संरचना xaddr *a, स्थिरांक संरचना xaddr *b)
{
	पूर्णांक i;

	जर (dst == रिक्त || a == रिक्त || b == रिक्त || a->af != b->af)
		परत (-1);

	स_नकल(dst, a, आकार(*dst));
	निवड (a->af) {
	स्थिती AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		परत (0);
	स्थिती AF_INET6:
		साठी (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		परत (0);
	पूर्वनिर्धारित:
		परत (-1);
	}
}

पूर्णांक
addr_cmp(स्थिरांक संरचना xaddr *a, स्थिरांक संरचना xaddr *b)
{
	पूर्णांक i;

	जर (a->af != b->af)
		परत (a->af == AF_INET6 ? 1 : -1);

	निवड (a->af) {
	स्थिती AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		जर (a->v4.s_addr == b->v4.s_addr)
			परत 0;
		परत (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	स्थिती AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		साठी (i = 0; i < 16; i++)
			जर (a->addr8[i] - b->addr8[i] != 0)
				परत (a->addr8[i] - b->addr8[i]);
		जर (a->scope_id == b->scope_id)
			परत (0);
		परत (a->scope_id > b->scope_id ? 1 : -1);
	पूर्वनिर्धारित:
		परत (-1);
	}
}

स्थिर पूर्णांक
addr_is_all0s(स्थिरांक संरचना xaddr *a)
{
	पूर्णांक i;

	निवड (a->af) {
	स्थिती AF_INET:
		परत (a->v4.s_addr == 0 ? 0 : -1);
	स्थिती AF_INET6:
		साठी (i = 0; i < 4; i++)
			जर (a->addr32[i] != 0)
				परत -1;
		परत 0;
	पूर्वनिर्धारित:
		परत -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
शून्य
addr_increment(संरचना xaddr *a)
{
	पूर्णांक i;
	uint32_t n;

	निवड (a->af) {
	स्थिती AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		थांबा;
	स्थिती AF_INET6:
		साठी (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			जर (n != 0)
				थांबा;
		}
		थांबा;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
स्थिर पूर्णांक
addr_host_is_all0s(स्थिरांक संरचना xaddr *a, u_int masklen)
{
	संरचना xaddr tmp_addr, tmp_mask, tmp_result;

	स_नकल(&tmp_addr, a, आकार(tmp_addr));
	जर (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		परत -1;
	जर (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		परत -1;
	परत addr_is_all0s(&tmp_result);
}

#जर 0
स्थिर पूर्णांक
addr_host_to_all0s(संरचना xaddr *a, u_int masklen)
{
	संरचना xaddr tmp_mask;

	जर (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		परत (-1);
	जर (addr_and(a, a, &tmp_mask) == -1)
		परत (-1);
	परत (0);
}
#endif

पूर्णांक
addr_host_to_all1s(संरचना xaddr *a, u_int masklen)
{
	संरचना xaddr tmp_mask;

	जर (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		परत (-1);
	जर (addr_or(a, a, &tmp_mask) == -1)
		परत (-1);
	परत (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
पूर्णांक
addr_pton(स्थिरांक अक्षर *p, संरचना xaddr *n)
{
	संरचना addrinfo hints, *ai;

	स_रखो(&hints, '\0', आकार(hints));
	hints.ai_flags = AI_NUMERICHOST;

	जर (p == रिक्त || getaddrinfo(p, रिक्त, &hints, &ai) != 0)
		परत -1;

	जर (ai == रिक्त)
		परत -1;

	जर (ai->ai_addr == रिक्त) {
		freeaddrinfo(ai);
		परत -1;
	}

	जर (n != रिक्त && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		परत -1;
	}

	freeaddrinfo(ai);
	परत 0;
}

#जर 0
स्थिर पूर्णांक
addr_sa_pton(स्थिरांक अक्षर *h, स्थिरांक अक्षर *s, संरचना sockaddr *sa, socklen_t slen)
{
	संरचना addrinfo hints, *ai;

	स_रखो(&hints, '\0', आकार(hints));
	hints.ai_flags = AI_NUMERICHOST;

	जर (h == रिक्त || getaddrinfo(h, s, &hints, &ai) != 0)
		परत -1;

	जर (ai == रिक्त)
		परत -1;

	जर (ai->ai_addr == रिक्त) {
		freeaddrinfo(ai);
		परत -1;
	}

	जर (sa != रिक्त) {
		जर (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			परत -1;
		}
		स_नकल(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	परत 0;
}
#endif

पूर्णांक
addr_ntop(स्थिरांक संरचना xaddr *n, अक्षर *p, माप_प्रकार len)
{
	संरचना sockaddr_storage ss;
	socklen_t slen = आकार(ss);

	जर (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		परत -1;
	जर (p == रिक्त || len == 0)
		परत -1;
	जर (getnameinfo(_SA(&ss), slen, p, len, रिक्त, 0,
	    NI_NUMERICHOST) != 0)
		परत -1;

	परत 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
पूर्णांक
addr_pton_cidr(स्थिरांक अक्षर *p, संरचना xaddr *n, u_int *l)
{
	संरचना xaddr tmp;
	u_int masklen = 999;
	अक्षर addrbuf[64], *mp;
	स्थिरांक अक्षर *errstr;

	/* Don't modify argument */
	जर (p == रिक्त || strlcpy(addrbuf, p, आकार(addrbuf)) >= आकार(addrbuf))
		परत -1;

	जर ((mp = म_अक्षर(addrbuf, '/')) != रिक्त) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, पूर्णांक_उच्च, &errstr);
		जर (errstr)
			परत -1;
	}

	जर (addr_pton(addrbuf, &tmp) == -1)
		परत -1;

	जर (mp == रिक्त)
		masklen = addr_unicast_masklen(tmp.af);
	जर (masklen_valid(tmp.af, masklen) == -1)
		परत -2;
	जर (addr_host_is_all0s(&tmp, masklen) != 0)
		परत -2;

	जर (n != रिक्त)
		स_नकल(n, &tmp, आकार(*n));
	जर (l != रिक्त)
		*l = masklen;

	परत 0;
}

पूर्णांक
addr_netmatch(स्थिरांक संरचना xaddr *host, स्थिरांक संरचना xaddr *net, u_int masklen)
{
	संरचना xaddr tmp_mask, tmp_result;

	जर (host->af != net->af)
		परत -1;

	जर (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		परत -1;
	जर (addr_and(&tmp_result, host, &tmp_mask) == -1)
		परत -1;
	परत addr_cmp(&tmp_result, net);
}
