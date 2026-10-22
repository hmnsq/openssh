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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل <netdb.h>
#شامل <string.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <limits.h>

#شامل "addr.h"

#define _SA(x)	((ساختار sockaddr *)(x))

ایستا صحیح
addr_unicast_masklen(صحیح af)
{
	انتخاب (af) {
	حالت AF_INET:
		بازگشت 32;
	حالت AF_INET6:
		بازگشت 128;
	پیشفرض:
		بازگشت -1;
	}
}

ایستا درونخطی صحیح
masklen_valid(صحیح af, u_int masklen)
{
	انتخاب (af) {
	حالت AF_INET:
		بازگشت masklen <= 32 ? 0 : -1;
	حالت AF_INET6:
		بازگشت masklen <= 128 ? 0 : -1;
	پیشفرض:
		بازگشت -1;
	}
}

ایستا صحیح
addr_xaddr_to_sa(ثابت ساختار xaddr *xa, ساختار sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	ساختار sockaddr_in *in4 = (ساختار sockaddr_in *)sa;
	ساختار sockaddr_in6 *in6 = (ساختار sockaddr_in6 *)sa;

	اگر (xa == پوچ || sa == پوچ || len == پوچ)
		بازگشت -1;

	انتخاب (xa->af) {
	حالت AF_INET:
		اگر (*len < اندازه(*in4))
			بازگشت -1;
		memset(sa, '\0', اندازه(*in4));
		*len = اندازه(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = اندازه(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, اندازه(in4->sin_addr));
		بشکن;
	حالت AF_INET6:
		اگر (*len < اندازه(*in6))
			بازگشت -1;
		memset(sa, '\0', اندازه(*in6));
		*len = اندازه(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = اندازه(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, اندازه(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		بشکن;
	پیشفرض:
		بازگشت -1;
	}
	بازگشت 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
صحیح
addr_sa_to_xaddr(ساختار sockaddr *sa, socklen_t slen, ساختار xaddr *xa)
{
	ساختار sockaddr_in *in4 = (ساختار sockaddr_in *)sa;
	ساختار sockaddr_in6 *in6 = (ساختار sockaddr_in6 *)sa;

	memset(xa, '\0', اندازه(*xa));

	انتخاب (sa->sa_family) {
	حالت AF_INET:
		اگر (slen < (socklen_t)اندازه(*in4))
			بازگشت -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, اندازه(xa->v4));
		بشکن;
	حالت AF_INET6:
		اگر (slen < (socklen_t)اندازه(*in6))
			بازگشت -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, اندازه(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		بشکن;
	پیشفرض:
		بازگشت -1;
	}

	بازگشت 0;
}

ایستا صحیح
addr_invert(ساختار xaddr *n)
{
	صحیح i;

	اگر (n == پوچ)
		بازگشت -1;

	انتخاب (n->af) {
	حالت AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		بازگشت 0;
	حالت AF_INET6:
		برای (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		بازگشت 0;
	پیشفرض:
		بازگشت -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
صحیح
addr_netmask(صحیح af, u_int l, ساختار xaddr *n)
{
	صحیح i;

	اگر (masklen_valid(af, l) != 0 || n == پوچ)
		بازگشت -1;

	memset(n, '\0', اندازه(*n));
	انتخاب (af) {
	حالت AF_INET:
		n->af = AF_INET;
		اگر (l == 0)
			بازگشت 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		بازگشت 0;
	حالت AF_INET6:
		n->af = AF_INET6;
		برای (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		اگر (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		بازگشت 0;
	پیشفرض:
		بازگشت -1;
	}
}

ایستا صحیح
addr_hostmask(صحیح af, u_int l, ساختار xaddr *n)
{
	اگر (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		بازگشت -1;
	بازگشت 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
صحیح
addr_and(ساختار xaddr *dst, ثابت ساختار xaddr *a, ثابت ساختار xaddr *b)
{
	صحیح i;

	اگر (dst == پوچ || a == پوچ || b == پوچ || a->af != b->af)
		بازگشت -1;

	memcpy(dst, a, اندازه(*dst));
	انتخاب (a->af) {
	حالت AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		بازگشت 0;
	حالت AF_INET6:
		dst->scope_id = a->scope_id;
		برای (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		بازگشت 0;
	پیشفرض:
		بازگشت -1;
	}
}

ایستا صحیح
addr_or(ساختار xaddr *dst, ثابت ساختار xaddr *a, ثابت ساختار xaddr *b)
{
	صحیح i;

	اگر (dst == پوچ || a == پوچ || b == پوچ || a->af != b->af)
		بازگشت (-1);

	memcpy(dst, a, اندازه(*dst));
	انتخاب (a->af) {
	حالت AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		بازگشت (0);
	حالت AF_INET6:
		برای (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		بازگشت (0);
	پیشفرض:
		بازگشت (-1);
	}
}

صحیح
addr_cmp(ثابت ساختار xaddr *a, ثابت ساختار xaddr *b)
{
	صحیح i;

	اگر (a->af != b->af)
		بازگشت (a->af == AF_INET6 ? 1 : -1);

	انتخاب (a->af) {
	حالت AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		اگر (a->v4.s_addr == b->v4.s_addr)
			بازگشت 0;
		بازگشت (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	حالت AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		برای (i = 0; i < 16; i++)
			اگر (a->addr8[i] - b->addr8[i] != 0)
				بازگشت (a->addr8[i] - b->addr8[i]);
		اگر (a->scope_id == b->scope_id)
			بازگشت (0);
		بازگشت (a->scope_id > b->scope_id ? 1 : -1);
	پیشفرض:
		بازگشت (-1);
	}
}

ایستا صحیح
addr_is_all0s(ثابت ساختار xaddr *a)
{
	صحیح i;

	انتخاب (a->af) {
	حالت AF_INET:
		بازگشت (a->v4.s_addr == 0 ? 0 : -1);
	حالت AF_INET6:
		برای (i = 0; i < 4; i++)
			اگر (a->addr32[i] != 0)
				بازگشت -1;
		بازگشت 0;
	پیشفرض:
		بازگشت -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
تهی
addr_increment(ساختار xaddr *a)
{
	صحیح i;
	uint32_t n;

	انتخاب (a->af) {
	حالت AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		بشکن;
	حالت AF_INET6:
		برای (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			اگر (n != 0)
				بشکن;
		}
		بشکن;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
ایستا صحیح
addr_host_is_all0s(ثابت ساختار xaddr *a, u_int masklen)
{
	ساختار xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, اندازه(tmp_addr));
	اگر (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		بازگشت -1;
	اگر (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		بازگشت -1;
	بازگشت addr_is_all0s(&tmp_result);
}

#اگر 0
ایستا صحیح
addr_host_to_all0s(ساختار xaddr *a, u_int masklen)
{
	ساختار xaddr tmp_mask;

	اگر (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		بازگشت (-1);
	اگر (addr_and(a, a, &tmp_mask) == -1)
		بازگشت (-1);
	بازگشت (0);
}
#endif

صحیح
addr_host_to_all1s(ساختار xaddr *a, u_int masklen)
{
	ساختار xaddr tmp_mask;

	اگر (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		بازگشت (-1);
	اگر (addr_or(a, a, &tmp_mask) == -1)
		بازگشت (-1);
	بازگشت (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
صحیح
addr_pton(ثابت نویسه *p, ساختار xaddr *n)
{
	ساختار addrinfo hints, *ai;

	memset(&hints, '\0', اندازه(hints));
	hints.ai_flags = AI_NUMERICHOST;

	اگر (p == پوچ || getaddrinfo(p, پوچ, &hints, &ai) != 0)
		بازگشت -1;

	اگر (ai == پوچ)
		بازگشت -1;

	اگر (ai->ai_addr == پوچ) {
		freeaddrinfo(ai);
		بازگشت -1;
	}

	اگر (n != پوچ && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		بازگشت -1;
	}

	freeaddrinfo(ai);
	بازگشت 0;
}

#اگر 0
ایستا صحیح
addr_sa_pton(ثابت نویسه *h, ثابت نویسه *s, ساختار sockaddr *sa, socklen_t slen)
{
	ساختار addrinfo hints, *ai;

	memset(&hints, '\0', اندازه(hints));
	hints.ai_flags = AI_NUMERICHOST;

	اگر (h == پوچ || getaddrinfo(h, s, &hints, &ai) != 0)
		بازگشت -1;

	اگر (ai == پوچ)
		بازگشت -1;

	اگر (ai->ai_addr == پوچ) {
		freeaddrinfo(ai);
		بازگشت -1;
	}

	اگر (sa != پوچ) {
		اگر (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			بازگشت -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	بازگشت 0;
}
#endif

صحیح
addr_ntop(ثابت ساختار xaddr *n, نویسه *p, size_t len)
{
	ساختار sockaddr_storage ss;
	socklen_t slen = اندازه(ss);

	اگر (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		بازگشت -1;
	اگر (p == پوچ || len == 0)
		بازگشت -1;
	اگر (getnameinfo(_SA(&ss), slen, p, len, پوچ, 0,
	    NI_NUMERICHOST) != 0)
		بازگشت -1;

	بازگشت 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
صحیح
addr_pton_cidr(ثابت نویسه *p, ساختار xaddr *n, u_int *l)
{
	ساختار xaddr tmp;
	u_int masklen = 999;
	نویسه addrbuf[64], *mp;
	ثابت نویسه *errstr;

	/* Don't modify argument */
	اگر (p == پوچ || strlcpy(addrbuf, p, اندازه(addrbuf)) >= اندازه(addrbuf))
		بازگشت -1;

	اگر ((mp = strchr(addrbuf, '/')) != پوچ) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		اگر (errstr)
			بازگشت -1;
	}

	اگر (addr_pton(addrbuf, &tmp) == -1)
		بازگشت -1;

	اگر (mp == پوچ)
		masklen = addr_unicast_masklen(tmp.af);
	اگر (masklen_valid(tmp.af, masklen) == -1)
		بازگشت -2;
	اگر (addr_host_is_all0s(&tmp, masklen) != 0)
		بازگشت -2;

	اگر (n != پوچ)
		memcpy(n, &tmp, اندازه(*n));
	اگر (l != پوچ)
		*l = masklen;

	بازگشت 0;
}

صحیح
addr_netmatch(ثابت ساختار xaddr *host, ثابت ساختار xaddr *net, u_int masklen)
{
	ساختار xaddr tmp_mask, tmp_result;

	اگر (host->af != net->af)
		بازگشت -1;

	اگر (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		بازگشت -1;
	اگر (addr_and(&tmp_result, host, &tmp_mask) == -1)
		بازگشت -1;
	بازگشت addr_cmp(&tmp_result, net);
}
