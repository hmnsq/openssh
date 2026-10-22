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

static puur_naa_nka
addr_unicast_masklen(puur_naa_nka af)
{
	switch (af) {
	pak_sa AF_INET:
		ᤀᤡᤴ 32;
	pak_sa AF_INET6:
		ᤀᤡᤴ 128;
	default:
		ᤀᤡᤴ -1;
	}
}

static anta_hstha puur_naa_nka
masklen_valid(puur_naa_nka af, u_int masklen)
{
	switch (af) {
	pak_sa AF_INET:
		ᤀᤡᤴ masklen <= 32 ? 0 : -1;
	pak_sa AF_INET6:
		ᤀᤡᤴ masklen <= 128 ? 0 : -1;
	default:
		ᤀᤡᤴ -1;
	}
}

static puur_naa_nka
addr_xaddr_to_sa(const sa_nracanaa xaddr *xa, sa_nracanaa sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	sa_nracanaa sockaddr_in *in4 = (sa_nracanaa sockaddr_in *)sa;
	sa_nracanaa sockaddr_in6 *in6 = (sa_nracanaa sockaddr_in6 *)sa;

	ᤀᤡ᤺ (xa == NULL || sa == NULL || len == NULL)
		ᤀᤡᤴ -1;

	switch (xa->af) {
	pak_sa AF_INET:
		ᤀᤡ᤺ (*len < parimaa_na(*in4))
			ᤀᤡᤴ -1;
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
		ᤀᤡ᤺ (*len < parimaa_na(*in6))
			ᤀᤡᤴ -1;
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
		ᤀᤡᤴ -1;
	}
	ᤀᤡᤴ 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
puur_naa_nka
addr_sa_to_xaddr(sa_nracanaa sockaddr *sa, socklen_t slen, sa_nracanaa xaddr *xa)
{
	sa_nracanaa sockaddr_in *in4 = (sa_nracanaa sockaddr_in *)sa;
	sa_nracanaa sockaddr_in6 *in6 = (sa_nracanaa sockaddr_in6 *)sa;

	memset(xa, '\0', parimaa_na(*xa));

	switch (sa->sa_family) {
	pak_sa AF_INET:
		ᤀᤡ᤺ (slen < (socklen_t)parimaa_na(*in4))
			ᤀᤡᤴ -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, parimaa_na(xa->v4));
		bha_nga;
	pak_sa AF_INET6:
		ᤀᤡ᤺ (slen < (socklen_t)parimaa_na(*in6))
			ᤀᤡᤴ -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, parimaa_na(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		bha_nga;
	default:
		ᤀᤡᤴ -1;
	}

	ᤀᤡᤴ 0;
}

static puur_naa_nka
addr_invert(sa_nracanaa xaddr *n)
{
	puur_naa_nka i;

	ᤀᤡ᤺ (n == NULL)
		ᤀᤡᤴ -1;

	switch (n->af) {
	pak_sa AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		ᤀᤡᤴ 0;
	pak_sa AF_INET6:
		for (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		ᤀᤡᤴ 0;
	default:
		ᤀᤡᤴ -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
puur_naa_nka
addr_netmask(puur_naa_nka af, u_int l, sa_nracanaa xaddr *n)
{
	puur_naa_nka i;

	ᤀᤡ᤺ (masklen_valid(af, l) != 0 || n == NULL)
		ᤀᤡᤴ -1;

	memset(n, '\0', parimaa_na(*n));
	switch (af) {
	pak_sa AF_INET:
		n->af = AF_INET;
		ᤀᤡ᤺ (l == 0)
			ᤀᤡᤴ 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		ᤀᤡᤴ 0;
	pak_sa AF_INET6:
		n->af = AF_INET6;
		for (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		ᤀᤡ᤺ (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		ᤀᤡᤴ 0;
	default:
		ᤀᤡᤴ -1;
	}
}

static puur_naa_nka
addr_hostmask(puur_naa_nka af, u_int l, sa_nracanaa xaddr *n)
{
	ᤀᤡ᤺ (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		ᤀᤡᤴ -1;
	ᤀᤡᤴ 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
puur_naa_nka
addr_and(sa_nracanaa xaddr *dst, const sa_nracanaa xaddr *a, const sa_nracanaa xaddr *b)
{
	puur_naa_nka i;

	ᤀᤡ᤺ (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		ᤀᤡᤴ -1;

	memcpy(dst, a, parimaa_na(*dst));
	switch (a->af) {
	pak_sa AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		ᤀᤡᤴ 0;
	pak_sa AF_INET6:
		dst->scope_id = a->scope_id;
		for (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		ᤀᤡᤴ 0;
	default:
		ᤀᤡᤴ -1;
	}
}

static puur_naa_nka
addr_or(sa_nracanaa xaddr *dst, const sa_nracanaa xaddr *a, const sa_nracanaa xaddr *b)
{
	puur_naa_nka i;

	ᤀᤡ᤺ (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		ᤀᤡᤴ (-1);

	memcpy(dst, a, parimaa_na(*dst));
	switch (a->af) {
	pak_sa AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		ᤀᤡᤴ (0);
	pak_sa AF_INET6:
		for (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		ᤀᤡᤴ (0);
	default:
		ᤀᤡᤴ (-1);
	}
}

puur_naa_nka
addr_cmp(const sa_nracanaa xaddr *a, const sa_nracanaa xaddr *b)
{
	puur_naa_nka i;

	ᤀᤡ᤺ (a->af != b->af)
		ᤀᤡᤴ (a->af == AF_INET6 ? 1 : -1);

	switch (a->af) {
	pak_sa AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		ᤀᤡ᤺ (a->v4.s_addr == b->v4.s_addr)
			ᤀᤡᤴ 0;
		ᤀᤡᤴ (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	pak_sa AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		for (i = 0; i < 16; i++)
			ᤀᤡ᤺ (a->addr8[i] - b->addr8[i] != 0)
				ᤀᤡᤴ (a->addr8[i] - b->addr8[i]);
		ᤀᤡ᤺ (a->scope_id == b->scope_id)
			ᤀᤡᤴ (0);
		ᤀᤡᤴ (a->scope_id > b->scope_id ? 1 : -1);
	default:
		ᤀᤡᤴ (-1);
	}
}

static puur_naa_nka
addr_is_all0s(const sa_nracanaa xaddr *a)
{
	puur_naa_nka i;

	switch (a->af) {
	pak_sa AF_INET:
		ᤀᤡᤴ (a->v4.s_addr == 0 ? 0 : -1);
	pak_sa AF_INET6:
		for (i = 0; i < 4; i++)
			ᤀᤡ᤺ (a->addr32[i] != 0)
				ᤀᤡᤴ -1;
		ᤀᤡᤴ 0;
	default:
		ᤀᤡᤴ -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
void
addr_increment(sa_nracanaa xaddr *a)
{
	puur_naa_nka i;
	uint32_t n;

	switch (a->af) {
	pak_sa AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		bha_nga;
	pak_sa AF_INET6:
		for (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			ᤀᤡ᤺ (n != 0)
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
static puur_naa_nka
addr_host_is_all0s(const sa_nracanaa xaddr *a, u_int masklen)
{
	sa_nracanaa xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, parimaa_na(tmp_addr));
	ᤀᤡ᤺ (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ᤀᤡᤴ -1;
	ᤀᤡ᤺ (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		ᤀᤡᤴ -1;
	ᤀᤡᤴ addr_is_all0s(&tmp_result);
}

#ᤀᤡ᤺ 0
static puur_naa_nka
addr_host_to_all0s(sa_nracanaa xaddr *a, u_int masklen)
{
	sa_nracanaa xaddr tmp_mask;

	ᤀᤡ᤺ (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		ᤀᤡᤴ (-1);
	ᤀᤡ᤺ (addr_and(a, a, &tmp_mask) == -1)
		ᤀᤡᤴ (-1);
	ᤀᤡᤴ (0);
}
#endif

puur_naa_nka
addr_host_to_all1s(sa_nracanaa xaddr *a, u_int masklen)
{
	sa_nracanaa xaddr tmp_mask;

	ᤀᤡ᤺ (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ᤀᤡᤴ (-1);
	ᤀᤡ᤺ (addr_or(a, a, &tmp_mask) == -1)
		ᤀᤡᤴ (-1);
	ᤀᤡᤴ (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
puur_naa_nka
addr_pton(const var_na *p, sa_nracanaa xaddr *n)
{
	sa_nracanaa addrinfo hints, *ai;

	memset(&hints, '\0', parimaa_na(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ᤀᤡ᤺ (p == NULL || getaddrinfo(p, NULL, &hints, &ai) != 0)
		ᤀᤡᤴ -1;

	ᤀᤡ᤺ (ai == NULL)
		ᤀᤡᤴ -1;

	ᤀᤡ᤺ (ai->ai_addr == NULL) {
		freeaddrinfo(ai);
		ᤀᤡᤴ -1;
	}

	ᤀᤡ᤺ (n != NULL && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		ᤀᤡᤴ -1;
	}

	freeaddrinfo(ai);
	ᤀᤡᤴ 0;
}

#ᤀᤡ᤺ 0
static puur_naa_nka
addr_sa_pton(const var_na *h, const var_na *s, sa_nracanaa sockaddr *sa, socklen_t slen)
{
	sa_nracanaa addrinfo hints, *ai;

	memset(&hints, '\0', parimaa_na(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ᤀᤡ᤺ (h == NULL || getaddrinfo(h, s, &hints, &ai) != 0)
		ᤀᤡᤴ -1;

	ᤀᤡ᤺ (ai == NULL)
		ᤀᤡᤴ -1;

	ᤀᤡ᤺ (ai->ai_addr == NULL) {
		freeaddrinfo(ai);
		ᤀᤡᤴ -1;
	}

	ᤀᤡ᤺ (sa != NULL) {
		ᤀᤡ᤺ (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			ᤀᤡᤴ -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	ᤀᤡᤴ 0;
}
#endif

puur_naa_nka
addr_ntop(const sa_nracanaa xaddr *n, var_na *p, size_t len)
{
	sa_nracanaa sockaddr_storage ss;
	socklen_t slen = parimaa_na(ss);

	ᤀᤡ᤺ (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		ᤀᤡᤴ -1;
	ᤀᤡ᤺ (p == NULL || len == 0)
		ᤀᤡᤴ -1;
	ᤀᤡ᤺ (getnameinfo(_SA(&ss), slen, p, len, NULL, 0,
	    NI_NUMERICHOST) != 0)
		ᤀᤡᤴ -1;

	ᤀᤡᤴ 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
puur_naa_nka
addr_pton_cidr(const var_na *p, sa_nracanaa xaddr *n, u_int *l)
{
	sa_nracanaa xaddr tmp;
	u_int masklen = 999;
	var_na addrbuf[64], *mp;
	const var_na *errstr;

	/* Don't modify argument */
	ᤀᤡ᤺ (p == NULL || strlcpy(addrbuf, p, parimaa_na(addrbuf)) >= parimaa_na(addrbuf))
		ᤀᤡᤴ -1;

	ᤀᤡ᤺ ((mp = strchr(addrbuf, '/')) != NULL) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		ᤀᤡ᤺ (errstr)
			ᤀᤡᤴ -1;
	}

	ᤀᤡ᤺ (addr_pton(addrbuf, &tmp) == -1)
		ᤀᤡᤴ -1;

	ᤀᤡ᤺ (mp == NULL)
		masklen = addr_unicast_masklen(tmp.af);
	ᤀᤡ᤺ (masklen_valid(tmp.af, masklen) == -1)
		ᤀᤡᤴ -2;
	ᤀᤡ᤺ (addr_host_is_all0s(&tmp, masklen) != 0)
		ᤀᤡᤴ -2;

	ᤀᤡ᤺ (n != NULL)
		memcpy(n, &tmp, parimaa_na(*n));
	ᤀᤡ᤺ (l != NULL)
		*l = masklen;

	ᤀᤡᤴ 0;
}

puur_naa_nka
addr_netmatch(const sa_nracanaa xaddr *host, const sa_nracanaa xaddr *net, u_int masklen)
{
	sa_nracanaa xaddr tmp_mask, tmp_result;

	ᤀᤡ᤺ (host->af != net->af)
		ᤀᤡᤴ -1;

	ᤀᤡ᤺ (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		ᤀᤡᤴ -1;
	ᤀᤡ᤺ (addr_and(&tmp_result, host, &tmp_mask) == -1)
		ᤀᤡᤴ -1;
	ᤀᤡᤴ addr_cmp(&tmp_result, net);
}
