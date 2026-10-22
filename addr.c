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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "addr.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _SA(x)	((ਬਣਤਰ sockaddr *)(x))

ਸਥਿਰ ਪੂਰਨ
addr_unicast_masklen(ਪੂਰਨ af)
{
	ਚੋਣ (af) {
	ਹਾਲਤ AF_INET:
		ਵਾਪਸ 32;
	ਹਾਲਤ AF_INET6:
		ਵਾਪਸ 128;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

ਸਥਿਰ ਸਤਰਅੰਦਰ ਪੂਰਨ
masklen_valid(ਪੂਰਨ af, u_int masklen)
{
	ਚੋਣ (af) {
	ਹਾਲਤ AF_INET:
		ਵਾਪਸ masklen <= 32 ? 0 : -1;
	ਹਾਲਤ AF_INET6:
		ਵਾਪਸ masklen <= 128 ? 0 : -1;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

ਸਥਿਰ ਪੂਰਨ
addr_xaddr_ਮੰਜ਼ਿਲ_sa(ਅਚਲ ਬਣਤਰ xaddr *xa, ਬਣਤਰ sockaddr *sa, socklen_t *len,
    uint16_t ਪੋਰਟ)
{
	ਬਣਤਰ sockaddr_in *in4 = (ਬਣਤਰ sockaddr_in *)sa;
	ਬਣਤਰ sockaddr_in6 *in6 = (ਬਣਤਰ sockaddr_in6 *)sa;

	ਜੇ (xa == ਨਿਰਾ || sa == ਨਿਰਾ || len == ਨਿਰਾ)
		ਵਾਪਸ -1;

	ਚੋਣ (xa->af) {
	ਹਾਲਤ AF_INET:
		ਜੇ (*len < ਆਕਾਰ(*in4))
			ਵਾਪਸ -1;
		memset(sa, '\0', ਆਕਾਰ(*in4));
		*len = ਆਕਾਰ(*in4);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SOCK_HAS_LEN
		in4->sin_len = ਆਕਾਰ(*in4);
#ਜੇ_ਅੰਤ
		in4->sin_family = AF_INET;
		in4->sin_port = htons(ਪੋਰਟ);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(&in4->sin_addr, &xa->v4, ਆਕਾਰ(in4->sin_addr));
		ਰੋਕੋ;
	ਹਾਲਤ AF_INET6:
		ਜੇ (*len < ਆਕਾਰ(*in6))
			ਵਾਪਸ -1;
		memset(sa, '\0', ਆਕਾਰ(*in6));
		*len = ਆਕਾਰ(*in6);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SOCK_HAS_LEN
		in6->sin6_len = ਆਕਾਰ(*in6);
#ਜੇ_ਅੰਤ
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(ਪੋਰਟ);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(&in6->sin6_addr, &xa->v6, ਆਕਾਰ(in6->sin6_addr));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#ਜੇ_ਅੰਤ
		ਰੋਕੋ;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
ਪੂਰਨ
addr_sa_ਮੰਜ਼ਿਲ_xaddr(ਬਣਤਰ sockaddr *sa, socklen_t slen, ਬਣਤਰ xaddr *xa)
{
	ਬਣਤਰ sockaddr_in *in4 = (ਬਣਤਰ sockaddr_in *)sa;
	ਬਣਤਰ sockaddr_in6 *in6 = (ਬਣਤਰ sockaddr_in6 *)sa;

	memset(xa, '\0', ਆਕਾਰ(*xa));

	ਚੋਣ (sa->sa_family) {
	ਹਾਲਤ AF_INET:
		ਜੇ (slen < (socklen_t)ਆਕਾਰ(*in4))
			ਵਾਪਸ -1;
		xa->af = AF_INET;
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(&xa->v4, &in4->sin_addr, ਆਕਾਰ(xa->v4));
		ਰੋਕੋ;
	ਹਾਲਤ AF_INET6:
		ਜੇ (slen < (socklen_t)ਆਕਾਰ(*in6))
			ਵਾਪਸ -1;
		xa->af = AF_INET6;
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(&xa->v6, &in6->sin6_addr, ਆਕਾਰ(xa->v6));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#ਜੇ_ਅੰਤ
		ਰੋਕੋ;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
addr_invert(ਬਣਤਰ xaddr *n)
{
	ਪੂਰਨ i;

	ਜੇ (n == ਨਿਰਾ)
		ਵਾਪਸ -1;

	ਚੋਣ (n->af) {
	ਹਾਲਤ AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		ਵਾਪਸ 0;
	ਹਾਲਤ AF_INET6:
		ਲਈ (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		ਵਾਪਸ 0;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
ਪੂਰਨ
addr_netmask(ਪੂਰਨ af, u_int l, ਬਣਤਰ xaddr *n)
{
	ਪੂਰਨ i;

	ਜੇ (masklen_valid(af, l) != 0 || n == ਨਿਰਾ)
		ਵਾਪਸ -1;

	memset(n, '\0', ਆਕਾਰ(*n));
	ਚੋਣ (af) {
	ਹਾਲਤ AF_INET:
		n->af = AF_INET;
		ਜੇ (l == 0)
			ਵਾਪਸ 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		ਵਾਪਸ 0;
	ਹਾਲਤ AF_INET6:
		n->af = AF_INET6;
		ਲਈ (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		ਜੇ (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		ਵਾਪਸ 0;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

ਸਥਿਰ ਪੂਰਨ
addr_hostmask(ਪੂਰਨ af, u_int l, ਬਣਤਰ xaddr *n)
{
	ਜੇ (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		ਵਾਪਸ -1;
	ਵਾਪਸ 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
ਪੂਰਨ
addr_and(ਬਣਤਰ xaddr *dst, ਅਚਲ ਬਣਤਰ xaddr *a, ਅਚਲ ਬਣਤਰ xaddr *b)
{
	ਪੂਰਨ i;

	ਜੇ (dst == ਨਿਰਾ || a == ਨਿਰਾ || b == ਨਿਰਾ || a->af != b->af)
		ਵਾਪਸ -1;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(dst, a, ਆਕਾਰ(*dst));
	ਚੋਣ (a->af) {
	ਹਾਲਤ AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		ਵਾਪਸ 0;
	ਹਾਲਤ AF_INET6:
		dst->scope_id = a->scope_id;
		ਲਈ (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		ਵਾਪਸ 0;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

ਸਥਿਰ ਪੂਰਨ
addr_or(ਬਣਤਰ xaddr *dst, ਅਚਲ ਬਣਤਰ xaddr *a, ਅਚਲ ਬਣਤਰ xaddr *b)
{
	ਪੂਰਨ i;

	ਜੇ (dst == ਨਿਰਾ || a == ਨਿਰਾ || b == ਨਿਰਾ || a->af != b->af)
		ਵਾਪਸ (-1);

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(dst, a, ਆਕਾਰ(*dst));
	ਚੋਣ (a->af) {
	ਹਾਲਤ AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		ਵਾਪਸ (0);
	ਹਾਲਤ AF_INET6:
		ਲਈ (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		ਵਾਪਸ (0);
	ਮੂਲ:
		ਵਾਪਸ (-1);
	}
}

ਪੂਰਨ
addr_cmp(ਅਚਲ ਬਣਤਰ xaddr *a, ਅਚਲ ਬਣਤਰ xaddr *b)
{
	ਪੂਰਨ i;

	ਜੇ (a->af != b->af)
		ਵਾਪਸ (a->af == AF_INET6 ? 1 : -1);

	ਚੋਣ (a->af) {
	ਹਾਲਤ AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		ਜੇ (a->v4.s_addr == b->v4.s_addr)
			ਵਾਪਸ 0;
		ਵਾਪਸ (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	ਹਾਲਤ AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		ਲਈ (i = 0; i < 16; i++)
			ਜੇ (a->addr8[i] - b->addr8[i] != 0)
				ਵਾਪਸ (a->addr8[i] - b->addr8[i]);
		ਜੇ (a->scope_id == b->scope_id)
			ਵਾਪਸ (0);
		ਵਾਪਸ (a->scope_id > b->scope_id ? 1 : -1);
	ਮੂਲ:
		ਵਾਪਸ (-1);
	}
}

ਸਥਿਰ ਪੂਰਨ
addr_is_all0s(ਅਚਲ ਬਣਤਰ xaddr *a)
{
	ਪੂਰਨ i;

	ਚੋਣ (a->af) {
	ਹਾਲਤ AF_INET:
		ਵਾਪਸ (a->v4.s_addr == 0 ? 0 : -1);
	ਹਾਲਤ AF_INET6:
		ਲਈ (i = 0; i < 4; i++)
			ਜੇ (a->addr32[i] != 0)
				ਵਾਪਸ -1;
		ਵਾਪਸ 0;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
ਖਾਲੀ
addr_increment(ਬਣਤਰ xaddr *a)
{
	ਪੂਰਨ i;
	uint32_t n;

	ਚੋਣ (a->af) {
	ਹਾਲਤ AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		ਰੋਕੋ;
	ਹਾਲਤ AF_INET6:
		ਲਈ (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			ਜੇ (n != 0)
				ਰੋਕੋ;
		}
		ਰੋਕੋ;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
ਸਥਿਰ ਪੂਰਨ
addr_host_is_all0s(ਅਚਲ ਬਣਤਰ xaddr *a, u_int masklen)
{
	ਬਣਤਰ xaddr tmp_addr, tmp_ਨਕਾਬ, tmp_ਨਤੀਜਾ;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(&tmp_addr, a, ਆਕਾਰ(tmp_addr));
	ਜੇ (addr_hostmask(a->af, masklen, &tmp_ਨਕਾਬ) == -1)
		ਵਾਪਸ -1;
	ਜੇ (addr_and(&tmp_ਨਤੀਜਾ, &tmp_addr, &tmp_ਨਕਾਬ) == -1)
		ਵਾਪਸ -1;
	ਵਾਪਸ addr_is_all0s(&tmp_ਨਤੀਜਾ);
}

#ਜੇ 0
ਸਥਿਰ ਪੂਰਨ
addr_host_ਮੰਜ਼ਿਲ_all0s(ਬਣਤਰ xaddr *a, u_int masklen)
{
	ਬਣਤਰ xaddr tmp_ਨਕਾਬ;

	ਜੇ (addr_netmask(a->af, masklen, &tmp_ਨਕਾਬ) == -1)
		ਵਾਪਸ (-1);
	ਜੇ (addr_and(a, a, &tmp_ਨਕਾਬ) == -1)
		ਵਾਪਸ (-1);
	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
addr_host_ਮੰਜ਼ਿਲ_all1s(ਬਣਤਰ xaddr *a, u_int masklen)
{
	ਬਣਤਰ xaddr tmp_ਨਕਾਬ;

	ਜੇ (addr_hostmask(a->af, masklen, &tmp_ਨਕਾਬ) == -1)
		ਵਾਪਸ (-1);
	ਜੇ (addr_or(a, a, &tmp_ਨਕਾਬ) == -1)
		ਵਾਪਸ (-1);
	ਵਾਪਸ (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
ਪੂਰਨ
addr_pton(ਅਚਲ ਅੱਖਰ *p, ਬਣਤਰ xaddr *n)
{
	ਬਣਤਰ addrinfo hints, *ai;

	memset(&hints, '\0', ਆਕਾਰ(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ਜੇ (p == ਨਿਰਾ || getaddrinfo(p, ਨਿਰਾ, &hints, &ai) != 0)
		ਵਾਪਸ -1;

	ਜੇ (ai == ਨਿਰਾ)
		ਵਾਪਸ -1;

	ਜੇ (ai->ai_addr == ਨਿਰਾ) {
		freeaddrinfo(ai);
		ਵਾਪਸ -1;
	}

	ਜੇ (n != ਨਿਰਾ && addr_sa_ਮੰਜ਼ਿਲ_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		ਵਾਪਸ -1;
	}

	freeaddrinfo(ai);
	ਵਾਪਸ 0;
}

#ਜੇ 0
ਸਥਿਰ ਪੂਰਨ
addr_sa_pton(ਅਚਲ ਅੱਖਰ *h, ਅਚਲ ਅੱਖਰ *s, ਬਣਤਰ sockaddr *sa, socklen_t slen)
{
	ਬਣਤਰ addrinfo hints, *ai;

	memset(&hints, '\0', ਆਕਾਰ(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ਜੇ (h == ਨਿਰਾ || getaddrinfo(h, s, &hints, &ai) != 0)
		ਵਾਪਸ -1;

	ਜੇ (ai == ਨਿਰਾ)
		ਵਾਪਸ -1;

	ਜੇ (ai->ai_addr == ਨਿਰਾ) {
		freeaddrinfo(ai);
		ਵਾਪਸ -1;
	}

	ਜੇ (sa != ਨਿਰਾ) {
		ਜੇ (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			ਵਾਪਸ -1;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
addr_ntop(ਅਚਲ ਬਣਤਰ xaddr *n, ਅੱਖਰ *p, ਮਾਪ_t len)
{
	ਬਣਤਰ sockaddr_storage ss;
	socklen_t slen = ਆਕਾਰ(ss);

	ਜੇ (addr_xaddr_ਮੰਜ਼ਿਲ_sa(n, _SA(&ss), &slen, 0) == -1)
		ਵਾਪਸ -1;
	ਜੇ (p == ਨਿਰਾ || len == 0)
		ਵਾਪਸ -1;
	ਜੇ (getnameinfo(_SA(&ss), slen, p, len, ਨਿਰਾ, 0,
	    NI_NUMERICHOST) != 0)
		ਵਾਪਸ -1;

	ਵਾਪਸ 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
ਪੂਰਨ
addr_pton_cidr(ਅਚਲ ਅੱਖਰ *p, ਬਣਤਰ xaddr *n, u_int *l)
{
	ਬਣਤਰ xaddr tmp;
	u_int masklen = 999;
	ਅੱਖਰ addrbuf[64], *mp;
	ਅਚਲ ਅੱਖਰ *errstr;

	/* Don't modify argument */
	ਜੇ (p == ਨਿਰਾ || strlcpy(addrbuf, p, ਆਕਾਰ(addrbuf)) >= ਆਕਾਰ(addrbuf))
		ਵਾਪਸ -1;

	ਜੇ ((mp = strchr(addrbuf, '/')) != ਨਿਰਾ) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &errstr);
		ਜੇ (errstr)
			ਵਾਪਸ -1;
	}

	ਜੇ (addr_pton(addrbuf, &tmp) == -1)
		ਵਾਪਸ -1;

	ਜੇ (mp == ਨਿਰਾ)
		masklen = addr_unicast_masklen(tmp.af);
	ਜੇ (masklen_valid(tmp.af, masklen) == -1)
		ਵਾਪਸ -2;
	ਜੇ (addr_host_is_all0s(&tmp, masklen) != 0)
		ਵਾਪਸ -2;

	ਜੇ (n != ਨਿਰਾ)
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(n, &tmp, ਆਕਾਰ(*n));
	ਜੇ (l != ਨਿਰਾ)
		*l = masklen;

	ਵਾਪਸ 0;
}

ਪੂਰਨ
addr_netmatch(ਅਚਲ ਬਣਤਰ xaddr *host, ਅਚਲ ਬਣਤਰ xaddr *net, u_int masklen)
{
	ਬਣਤਰ xaddr tmp_ਨਕਾਬ, tmp_ਨਤੀਜਾ;

	ਜੇ (host->af != net->af)
		ਵਾਪਸ -1;

	ਜੇ (addr_netmask(host->af, masklen, &tmp_ਨਕਾਬ) == -1)
		ਵਾਪਸ -1;
	ਜੇ (addr_and(&tmp_ਨਤੀਜਾ, host, &tmp_ਨਕਾਬ) == -1)
		ਵਾਪਸ -1;
	ਵਾਪਸ addr_cmp(&tmp_ਨਤੀਜਾ, net);
}
