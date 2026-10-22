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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>

#ضمن <netdb.h>
#ضمن <string.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <limits.h>

#ضمن "addr.h"

#define _SA(x)	((بنية sockaddr *)(x))

ساكن صحيح
addr_unicast_masklen(صحيح af)
{
	بدل (af) {
	حالة AF_INET:
		أرجع 32;
	حالة AF_INET6:
		أرجع 128;
	افتراضي:
		أرجع -1;
	}
}

ساكن مضمن صحيح
masklen_valid(صحيح af, u_int masklen)
{
	بدل (af) {
	حالة AF_INET:
		أرجع masklen <= 32 ? 0 : -1;
	حالة AF_INET6:
		أرجع masklen <= 128 ? 0 : -1;
	افتراضي:
		أرجع -1;
	}
}

ساكن صحيح
addr_xaddr_to_sa(ثابت بنية xaddr *xa, بنية sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	بنية sockaddr_in *in4 = (بنية sockaddr_in *)sa;
	بنية sockaddr_in6 *in6 = (بنية sockaddr_in6 *)sa;

	𐡄𐡍 (xa == عدم || sa == عدم || len == عدم)
		أرجع -1;

	بدل (xa->af) {
	حالة AF_INET:
		𐡄𐡍 (*len < حجم(*in4))
			أرجع -1;
		memset(sa, '\0', حجم(*in4));
		*len = حجم(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = حجم(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, حجم(in4->sin_addr));
		اكسر;
	حالة AF_INET6:
		𐡄𐡍 (*len < حجم(*in6))
			أرجع -1;
		memset(sa, '\0', حجم(*in6));
		*len = حجم(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = حجم(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, حجم(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		اكسر;
	افتراضي:
		أرجع -1;
	}
	أرجع 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
صحيح
addr_sa_to_xaddr(بنية sockaddr *sa, socklen_t slen, بنية xaddr *xa)
{
	بنية sockaddr_in *in4 = (بنية sockaddr_in *)sa;
	بنية sockaddr_in6 *in6 = (بنية sockaddr_in6 *)sa;

	memset(xa, '\0', حجم(*xa));

	بدل (sa->sa_family) {
	حالة AF_INET:
		𐡄𐡍 (slen < (socklen_t)حجم(*in4))
			أرجع -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, حجم(xa->v4));
		اكسر;
	حالة AF_INET6:
		𐡄𐡍 (slen < (socklen_t)حجم(*in6))
			أرجع -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, حجم(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		اكسر;
	افتراضي:
		أرجع -1;
	}

	أرجع 0;
}

ساكن صحيح
addr_invert(بنية xaddr *n)
{
	صحيح i;

	𐡄𐡍 (n == عدم)
		أرجع -1;

	بدل (n->af) {
	حالة AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		أرجع 0;
	حالة AF_INET6:
		لكل (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		أرجع 0;
	افتراضي:
		أرجع -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
صحيح
addr_netmask(صحيح af, u_int l, بنية xaddr *n)
{
	صحيح i;

	𐡄𐡍 (masklen_valid(af, l) != 0 || n == عدم)
		أرجع -1;

	memset(n, '\0', حجم(*n));
	بدل (af) {
	حالة AF_INET:
		n->af = AF_INET;
		𐡄𐡍 (l == 0)
			أرجع 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		أرجع 0;
	حالة AF_INET6:
		n->af = AF_INET6;
		لكل (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		𐡄𐡍 (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		أرجع 0;
	افتراضي:
		أرجع -1;
	}
}

ساكن صحيح
addr_hostmask(صحيح af, u_int l, بنية xaddr *n)
{
	𐡄𐡍 (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		أرجع -1;
	أرجع 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
صحيح
addr_and(بنية xaddr *dst, ثابت بنية xaddr *a, ثابت بنية xaddr *b)
{
	صحيح i;

	𐡄𐡍 (dst == عدم || a == عدم || b == عدم || a->af != b->af)
		أرجع -1;

	memcpy(dst, a, حجم(*dst));
	بدل (a->af) {
	حالة AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		أرجع 0;
	حالة AF_INET6:
		dst->scope_id = a->scope_id;
		لكل (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		أرجع 0;
	افتراضي:
		أرجع -1;
	}
}

ساكن صحيح
addr_or(بنية xaddr *dst, ثابت بنية xaddr *a, ثابت بنية xaddr *b)
{
	صحيح i;

	𐡄𐡍 (dst == عدم || a == عدم || b == عدم || a->af != b->af)
		أرجع (-1);

	memcpy(dst, a, حجم(*dst));
	بدل (a->af) {
	حالة AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		أرجع (0);
	حالة AF_INET6:
		لكل (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		أرجع (0);
	افتراضي:
		أرجع (-1);
	}
}

صحيح
addr_cmp(ثابت بنية xaddr *a, ثابت بنية xaddr *b)
{
	صحيح i;

	𐡄𐡍 (a->af != b->af)
		أرجع (a->af == AF_INET6 ? 1 : -1);

	بدل (a->af) {
	حالة AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		𐡄𐡍 (a->v4.s_addr == b->v4.s_addr)
			أرجع 0;
		أرجع (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	حالة AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		لكل (i = 0; i < 16; i++)
			𐡄𐡍 (a->addr8[i] - b->addr8[i] != 0)
				أرجع (a->addr8[i] - b->addr8[i]);
		𐡄𐡍 (a->scope_id == b->scope_id)
			أرجع (0);
		أرجع (a->scope_id > b->scope_id ? 1 : -1);
	افتراضي:
		أرجع (-1);
	}
}

ساكن صحيح
addr_is_all0s(ثابت بنية xaddr *a)
{
	صحيح i;

	بدل (a->af) {
	حالة AF_INET:
		أرجع (a->v4.s_addr == 0 ? 0 : -1);
	حالة AF_INET6:
		لكل (i = 0; i < 4; i++)
			𐡄𐡍 (a->addr32[i] != 0)
				أرجع -1;
		أرجع 0;
	افتراضي:
		أرجع -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
فراغ
addr_increment(بنية xaddr *a)
{
	صحيح i;
	uint32_t n;

	بدل (a->af) {
	حالة AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		اكسر;
	حالة AF_INET6:
		لكل (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			𐡄𐡍 (n != 0)
				اكسر;
		}
		اكسر;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
ساكن صحيح
addr_host_is_all0s(ثابت بنية xaddr *a, u_int masklen)
{
	بنية xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, حجم(tmp_addr));
	𐡄𐡍 (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		أرجع -1;
	𐡄𐡍 (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		أرجع -1;
	أرجع addr_is_all0s(&tmp_result);
}

#𐡄𐡍 0
ساكن صحيح
addr_host_to_all0s(بنية xaddr *a, u_int masklen)
{
	بنية xaddr tmp_mask;

	𐡄𐡍 (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		أرجع (-1);
	𐡄𐡍 (addr_and(a, a, &tmp_mask) == -1)
		أرجع (-1);
	أرجع (0);
}
#endif

صحيح
addr_host_to_all1s(بنية xaddr *a, u_int masklen)
{
	بنية xaddr tmp_mask;

	𐡄𐡍 (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		أرجع (-1);
	𐡄𐡍 (addr_or(a, a, &tmp_mask) == -1)
		أرجع (-1);
	أرجع (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
صحيح
addr_pton(ثابت حرف *p, بنية xaddr *n)
{
	بنية addrinfo hints, *ai;

	memset(&hints, '\0', حجم(hints));
	hints.ai_flags = AI_NUMERICHOST;

	𐡄𐡍 (p == عدم || getaddrinfo(p, عدم, &hints, &ai) != 0)
		أرجع -1;

	𐡄𐡍 (ai == عدم)
		أرجع -1;

	𐡄𐡍 (ai->ai_addr == عدم) {
		freeaddrinfo(ai);
		أرجع -1;
	}

	𐡄𐡍 (n != عدم && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		أرجع -1;
	}

	freeaddrinfo(ai);
	أرجع 0;
}

#𐡄𐡍 0
ساكن صحيح
addr_sa_pton(ثابت حرف *h, ثابت حرف *s, بنية sockaddr *sa, socklen_t slen)
{
	بنية addrinfo hints, *ai;

	memset(&hints, '\0', حجم(hints));
	hints.ai_flags = AI_NUMERICHOST;

	𐡄𐡍 (h == عدم || getaddrinfo(h, s, &hints, &ai) != 0)
		أرجع -1;

	𐡄𐡍 (ai == عدم)
		أرجع -1;

	𐡄𐡍 (ai->ai_addr == عدم) {
		freeaddrinfo(ai);
		أرجع -1;
	}

	𐡄𐡍 (sa != عدم) {
		𐡄𐡍 (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			أرجع -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	أرجع 0;
}
#endif

صحيح
addr_ntop(ثابت بنية xaddr *n, حرف *p, size_t len)
{
	بنية sockaddr_storage ss;
	socklen_t slen = حجم(ss);

	𐡄𐡍 (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		أرجع -1;
	𐡄𐡍 (p == عدم || len == 0)
		أرجع -1;
	𐡄𐡍 (getnameinfo(_SA(&ss), slen, p, len, عدم, 0,
	    NI_NUMERICHOST) != 0)
		أرجع -1;

	أرجع 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
صحيح
addr_pton_cidr(ثابت حرف *p, بنية xaddr *n, u_int *l)
{
	بنية xaddr tmp;
	u_int masklen = 999;
	حرف addrbuf[64], *mp;
	ثابت حرف *errstr;

	/* Don't modify argument */
	𐡄𐡍 (p == عدم || strlcpy(addrbuf, p, حجم(addrbuf)) >= حجم(addrbuf))
		أرجع -1;

	𐡄𐡍 ((mp = strchr(addrbuf, '/')) != عدم) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		𐡄𐡍 (errstr)
			أرجع -1;
	}

	𐡄𐡍 (addr_pton(addrbuf, &tmp) == -1)
		أرجع -1;

	𐡄𐡍 (mp == عدم)
		masklen = addr_unicast_masklen(tmp.af);
	𐡄𐡍 (masklen_valid(tmp.af, masklen) == -1)
		أرجع -2;
	𐡄𐡍 (addr_host_is_all0s(&tmp, masklen) != 0)
		أرجع -2;

	𐡄𐡍 (n != عدم)
		memcpy(n, &tmp, حجم(*n));
	𐡄𐡍 (l != عدم)
		*l = masklen;

	أرجع 0;
}

صحيح
addr_netmatch(ثابت بنية xaddr *host, ثابت بنية xaddr *net, u_int masklen)
{
	بنية xaddr tmp_mask, tmp_result;

	𐡄𐡍 (host->af != net->af)
		أرجع -1;

	𐡄𐡍 (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		أرجع -1;
	𐡄𐡍 (addr_and(&tmp_result, host, &tmp_mask) == -1)
		أرجع -1;
	أرجع addr_cmp(&tmp_result, net);
}
