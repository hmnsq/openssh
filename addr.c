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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "addr.h"

#define _SA(x)	((sa_nracanaa sockaddr *)(x))

static ကိန်းပြည့်
addr_unicast_masklen(ကိန်းပြည့် af)
{
	switch (af) {
	pak_sa AF_INET:
		ပြန်ပေး 32;
	pak_sa AF_INET6:
		ပြန်ပေး 128;
	default:
		ပြန်ပေး -1;
	}
}

static anta_hstha ကိန်းပြည့်
masklen_valid(ကိန်းပြည့် af, u_int masklen)
{
	switch (af) {
	pak_sa AF_INET:
		ပြန်ပေး masklen <= 32 ? 0 : -1;
	pak_sa AF_INET6:
		ပြန်ပေး masklen <= 128 ? 0 : -1;
	default:
		ပြန်ပေး -1;
	}
}

static ကိန်းပြည့်
addr_xaddr_to_sa(const sa_nracanaa xaddr *xa, sa_nracanaa sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	sa_nracanaa sockaddr_in *in4 = (sa_nracanaa sockaddr_in *)sa;
	sa_nracanaa sockaddr_in6 *in6 = (sa_nracanaa sockaddr_in6 *)sa;

	အကယ်၍ (xa == NULL || sa == NULL || len == NULL)
		ပြန်ပေး -1;

	switch (xa->af) {
	pak_sa AF_INET:
		အကယ်၍ (*len < parimaa_na(*in4))
			ပြန်ပေး -1;
		memset(sa, '\0', parimaa_na(*in4));
		*len = parimaa_na(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = parimaa_na(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, parimaa_na(in4->sin_addr));
		bha_nga;
	pak_sa AF_INET6:
		အကယ်၍ (*len < parimaa_na(*in6))
			ပြန်ပေး -1;
		memset(sa, '\0', parimaa_na(*in6));
		*len = parimaa_na(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = parimaa_na(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, parimaa_na(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		bha_nga;
	default:
		ပြန်ပေး -1;
	}
	ပြန်ပေး 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
ကိန်းပြည့်
addr_sa_to_xaddr(sa_nracanaa sockaddr *sa, socklen_t slen, sa_nracanaa xaddr *xa)
{
	sa_nracanaa sockaddr_in *in4 = (sa_nracanaa sockaddr_in *)sa;
	sa_nracanaa sockaddr_in6 *in6 = (sa_nracanaa sockaddr_in6 *)sa;

	memset(xa, '\0', parimaa_na(*xa));

	switch (sa->sa_family) {
	pak_sa AF_INET:
		အကယ်၍ (slen < (socklen_t)parimaa_na(*in4))
			ပြန်ပေး -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, parimaa_na(xa->v4));
		bha_nga;
	pak_sa AF_INET6:
		အကယ်၍ (slen < (socklen_t)parimaa_na(*in6))
			ပြန်ပေး -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, parimaa_na(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		bha_nga;
	default:
		ပြန်ပေး -1;
	}

	ပြန်ပေး 0;
}

static ကိန်းပြည့်
addr_invert(sa_nracanaa xaddr *n)
{
	ကိန်းပြည့် i;

	အကယ်၍ (n == NULL)
		ပြန်ပေး -1;

	switch (n->af) {
	pak_sa AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		ပြန်ပေး 0;
	pak_sa AF_INET6:
		အတွက် (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		ပြန်ပေး 0;
	default:
		ပြန်ပေး -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
ကိန်းပြည့်
addr_netmask(ကိန်းပြည့် af, u_int l, sa_nracanaa xaddr *n)
{
	ကိန်းပြည့် i;

	အကယ်၍ (masklen_valid(af, l) != 0 || n == NULL)
		ပြန်ပေး -1;

	memset(n, '\0', parimaa_na(*n));
	switch (af) {
	pak_sa AF_INET:
		n->af = AF_INET;
		အကယ်၍ (l == 0)
			ပြန်ပေး 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		ပြန်ပေး 0;
	pak_sa AF_INET6:
		n->af = AF_INET6;
		အတွက် (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		အကယ်၍ (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		ပြန်ပေး 0;
	default:
		ပြန်ပေး -1;
	}
}

static ကိန်းပြည့်
addr_hostmask(ကိန်းပြည့် af, u_int l, sa_nracanaa xaddr *n)
{
	အကယ်၍ (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		ပြန်ပေး -1;
	ပြန်ပေး 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
ကိန်းပြည့်
addr_and(sa_nracanaa xaddr *dst, const sa_nracanaa xaddr *a, const sa_nracanaa xaddr *b)
{
	ကိန်းပြည့် i;

	အကယ်၍ (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		ပြန်ပေး -1;

	memcpy(dst, a, parimaa_na(*dst));
	switch (a->af) {
	pak_sa AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		ပြန်ပေး 0;
	pak_sa AF_INET6:
		dst->scope_id = a->scope_id;
		အတွက် (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		ပြန်ပေး 0;
	default:
		ပြန်ပေး -1;
	}
}

static ကိန်းပြည့်
addr_or(sa_nracanaa xaddr *dst, const sa_nracanaa xaddr *a, const sa_nracanaa xaddr *b)
{
	ကိန်းပြည့် i;

	အကယ်၍ (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		ပြန်ပေး (-1);

	memcpy(dst, a, parimaa_na(*dst));
	switch (a->af) {
	pak_sa AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		ပြန်ပေး (0);
	pak_sa AF_INET6:
		အတွက် (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		ပြန်ပေး (0);
	default:
		ပြန်ပေး (-1);
	}
}

ကိန်းပြည့်
addr_cmp(const sa_nracanaa xaddr *a, const sa_nracanaa xaddr *b)
{
	ကိန်းပြည့် i;

	အကယ်၍ (a->af != b->af)
		ပြန်ပေး (a->af == AF_INET6 ? 1 : -1);

	switch (a->af) {
	pak_sa AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		အကယ်၍ (a->v4.s_addr == b->v4.s_addr)
			ပြန်ပေး 0;
		ပြန်ပေး (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	pak_sa AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		အတွက် (i = 0; i < 16; i++)
			အကယ်၍ (a->addr8[i] - b->addr8[i] != 0)
				ပြန်ပေး (a->addr8[i] - b->addr8[i]);
		အကယ်၍ (a->scope_id == b->scope_id)
			ပြန်ပေး (0);
		ပြန်ပေး (a->scope_id > b->scope_id ? 1 : -1);
	default:
		ပြန်ပေး (-1);
	}
}

static ကိန်းပြည့်
addr_is_all0s(const sa_nracanaa xaddr *a)
{
	ကိန်းပြည့် i;

	switch (a->af) {
	pak_sa AF_INET:
		ပြန်ပေး (a->v4.s_addr == 0 ? 0 : -1);
	pak_sa AF_INET6:
		အတွက် (i = 0; i < 4; i++)
			အကယ်၍ (a->addr32[i] != 0)
				ပြန်ပေး -1;
		ပြန်ပေး 0;
	default:
		ပြန်ပေး -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
void
addr_increment(sa_nracanaa xaddr *a)
{
	ကိန်းပြည့် i;
	uint32_t n;

	switch (a->af) {
	pak_sa AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		bha_nga;
	pak_sa AF_INET6:
		အတွက် (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			အကယ်၍ (n != 0)
				bha_nga;
		}
		bha_nga;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
static ကိန်းပြည့်
addr_host_is_all0s(const sa_nracanaa xaddr *a, u_int masklen)
{
	sa_nracanaa xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, parimaa_na(tmp_addr));
	အကယ်၍ (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ပြန်ပေး -1;
	အကယ်၍ (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		ပြန်ပေး -1;
	ပြန်ပေး addr_is_all0s(&tmp_result);
}

#အကယ်၍ 0
static ကိန်းပြည့်
addr_host_to_all0s(sa_nracanaa xaddr *a, u_int masklen)
{
	sa_nracanaa xaddr tmp_mask;

	အကယ်၍ (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		ပြန်ပေး (-1);
	အကယ်၍ (addr_and(a, a, &tmp_mask) == -1)
		ပြန်ပေး (-1);
	ပြန်ပေး (0);
}
#endif

ကိန်းပြည့်
addr_host_to_all1s(sa_nracanaa xaddr *a, u_int masklen)
{
	sa_nracanaa xaddr tmp_mask;

	အကယ်၍ (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ပြန်ပေး (-1);
	အကယ်၍ (addr_or(a, a, &tmp_mask) == -1)
		ပြန်ပေး (-1);
	ပြန်ပေး (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
ကိန်းပြည့်
addr_pton(const var_na *p, sa_nracanaa xaddr *n)
{
	sa_nracanaa addrinfo hints, *ai;

	memset(&hints, '\0', parimaa_na(hints));
	hints.ai_flags = AI_NUMERICHOST;

	အကယ်၍ (p == NULL || getaddrinfo(p, NULL, &hints, &ai) != 0)
		ပြန်ပေး -1;

	အကယ်၍ (ai == NULL)
		ပြန်ပေး -1;

	အကယ်၍ (ai->ai_addr == NULL) {
		freeaddrinfo(ai);
		ပြန်ပေး -1;
	}

	အကယ်၍ (n != NULL && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		ပြန်ပေး -1;
	}

	freeaddrinfo(ai);
	ပြန်ပေး 0;
}

#အကယ်၍ 0
static ကိန်းပြည့်
addr_sa_pton(const var_na *h, const var_na *s, sa_nracanaa sockaddr *sa, socklen_t slen)
{
	sa_nracanaa addrinfo hints, *ai;

	memset(&hints, '\0', parimaa_na(hints));
	hints.ai_flags = AI_NUMERICHOST;

	အကယ်၍ (h == NULL || getaddrinfo(h, s, &hints, &ai) != 0)
		ပြန်ပေး -1;

	အကယ်၍ (ai == NULL)
		ပြန်ပေး -1;

	အကယ်၍ (ai->ai_addr == NULL) {
		freeaddrinfo(ai);
		ပြန်ပေး -1;
	}

	အကယ်၍ (sa != NULL) {
		အကယ်၍ (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			ပြန်ပေး -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	ပြန်ပေး 0;
}
#endif

ကိန်းပြည့်
addr_ntop(const sa_nracanaa xaddr *n, var_na *p, size_t len)
{
	sa_nracanaa sockaddr_storage ss;
	socklen_t slen = parimaa_na(ss);

	အကယ်၍ (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		ပြန်ပေး -1;
	အကယ်၍ (p == NULL || len == 0)
		ပြန်ပေး -1;
	အကယ်၍ (getnameinfo(_SA(&ss), slen, p, len, NULL, 0,
	    NI_NUMERICHOST) != 0)
		ပြန်ပေး -1;

	ပြန်ပေး 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
ကိန်းပြည့်
addr_pton_cidr(const var_na *p, sa_nracanaa xaddr *n, u_int *l)
{
	sa_nracanaa xaddr tmp;
	u_int masklen = 999;
	var_na addrbuf[64], *mp;
	const var_na *errstr;

	/* Don't modify argument */
	အကယ်၍ (p == NULL || strlcpy(addrbuf, p, parimaa_na(addrbuf)) >= parimaa_na(addrbuf))
		ပြန်ပေး -1;

	အကယ်၍ ((mp = strchr(addrbuf, '/')) != NULL) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		အကယ်၍ (errstr)
			ပြန်ပေး -1;
	}

	အကယ်၍ (addr_pton(addrbuf, &tmp) == -1)
		ပြန်ပေး -1;

	အကယ်၍ (mp == NULL)
		masklen = addr_unicast_masklen(tmp.af);
	အကယ်၍ (masklen_valid(tmp.af, masklen) == -1)
		ပြန်ပေး -2;
	အကယ်၍ (addr_host_is_all0s(&tmp, masklen) != 0)
		ပြန်ပေး -2;

	အကယ်၍ (n != NULL)
		memcpy(n, &tmp, parimaa_na(*n));
	အကယ်၍ (l != NULL)
		*l = masklen;

	ပြန်ပေး 0;
}

ကိန်းပြည့်
addr_netmatch(const sa_nracanaa xaddr *host, const sa_nracanaa xaddr *net, u_int masklen)
{
	sa_nracanaa xaddr tmp_mask, tmp_result;

	အကယ်၍ (host->af != net->af)
		ပြန်ပေး -1;

	အကယ်၍ (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		ပြန်ပေး -1;
	အကယ်၍ (addr_and(&tmp_result, host, &tmp_mask) == -1)
		ပြန်ပေး -1;
	ပြန်ပေး addr_cmp(&tmp_result, net);
}
