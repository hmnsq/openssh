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

#define _SA(x)	((struct sockaddr *)(x))

static целое
addr_unicast_masklen(целое af)
{
	switch (af) {
	case AF_INET:
		вернуть 32;
	case AF_INET6:
		вернуть 128;
	default:
		вернуть -1;
	}
}

static inline целое
masklen_valid(целое af, u_int masklen)
{
	switch (af) {
	case AF_INET:
		вернуть masklen <= 32 ? 0 : -1;
	case AF_INET6:
		вернуть masklen <= 128 ? 0 : -1;
	default:
		вернуть -1;
	}
}

static целое
addr_xaddr_to_sa(const struct xaddr *xa, struct sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)sa;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;

	если (xa == NULL || sa == NULL || len == NULL)
		вернуть -1;

	switch (xa->af) {
	case AF_INET:
		если (*len < sizeof(*in4))
			вернуть -1;
		memset(sa, '\0', sizeof(*in4));
		*len = sizeof(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = sizeof(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, sizeof(in4->sin_addr));
		break;
	case AF_INET6:
		если (*len < sizeof(*in6))
			вернуть -1;
		memset(sa, '\0', sizeof(*in6));
		*len = sizeof(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = sizeof(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, sizeof(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		break;
	default:
		вернуть -1;
	}
	вернуть 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
целое
addr_sa_to_xaddr(struct sockaddr *sa, socklen_t slen, struct xaddr *xa)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)sa;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;

	memset(xa, '\0', sizeof(*xa));

	switch (sa->sa_family) {
	case AF_INET:
		если (slen < (socklen_t)sizeof(*in4))
			вернуть -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, sizeof(xa->v4));
		break;
	case AF_INET6:
		если (slen < (socklen_t)sizeof(*in6))
			вернуть -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, sizeof(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		break;
	default:
		вернуть -1;
	}

	вернуть 0;
}

static целое
addr_invert(struct xaddr *n)
{
	целое i;

	если (n == NULL)
		вернуть -1;

	switch (n->af) {
	case AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		вернуть 0;
	case AF_INET6:
		для (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		вернуть 0;
	default:
		вернуть -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
целое
addr_netmask(целое af, u_int l, struct xaddr *n)
{
	целое i;

	если (masklen_valid(af, l) != 0 || n == NULL)
		вернуть -1;

	memset(n, '\0', sizeof(*n));
	switch (af) {
	case AF_INET:
		n->af = AF_INET;
		если (l == 0)
			вернуть 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		вернуть 0;
	case AF_INET6:
		n->af = AF_INET6;
		для (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		если (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		вернуть 0;
	default:
		вернуть -1;
	}
}

static целое
addr_hostmask(целое af, u_int l, struct xaddr *n)
{
	если (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		вернуть -1;
	вернуть 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
целое
addr_and(struct xaddr *dst, const struct xaddr *a, const struct xaddr *b)
{
	целое i;

	если (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		вернуть -1;

	memcpy(dst, a, sizeof(*dst));
	switch (a->af) {
	case AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		вернуть 0;
	case AF_INET6:
		dst->scope_id = a->scope_id;
		для (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		вернуть 0;
	default:
		вернуть -1;
	}
}

static целое
addr_or(struct xaddr *dst, const struct xaddr *a, const struct xaddr *b)
{
	целое i;

	если (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		вернуть (-1);

	memcpy(dst, a, sizeof(*dst));
	switch (a->af) {
	case AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		вернуть (0);
	case AF_INET6:
		для (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		вернуть (0);
	default:
		вернуть (-1);
	}
}

целое
addr_cmp(const struct xaddr *a, const struct xaddr *b)
{
	целое i;

	если (a->af != b->af)
		вернуть (a->af == AF_INET6 ? 1 : -1);

	switch (a->af) {
	case AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		если (a->v4.s_addr == b->v4.s_addr)
			вернуть 0;
		вернуть (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	case AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		для (i = 0; i < 16; i++)
			если (a->addr8[i] - b->addr8[i] != 0)
				вернуть (a->addr8[i] - b->addr8[i]);
		если (a->scope_id == b->scope_id)
			вернуть (0);
		вернуть (a->scope_id > b->scope_id ? 1 : -1);
	default:
		вернуть (-1);
	}
}

static целое
addr_is_all0s(const struct xaddr *a)
{
	целое i;

	switch (a->af) {
	case AF_INET:
		вернуть (a->v4.s_addr == 0 ? 0 : -1);
	case AF_INET6:
		для (i = 0; i < 4; i++)
			если (a->addr32[i] != 0)
				вернуть -1;
		вернуть 0;
	default:
		вернуть -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
void
addr_increment(struct xaddr *a)
{
	целое i;
	uint32_t n;

	switch (a->af) {
	case AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		break;
	case AF_INET6:
		для (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			если (n != 0)
				break;
		}
		break;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
static целое
addr_host_is_all0s(const struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, sizeof(tmp_addr));
	если (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		вернуть -1;
	если (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		вернуть -1;
	вернуть addr_is_all0s(&tmp_result);
}

#если 0
static целое
addr_host_to_all0s(struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_mask;

	если (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		вернуть (-1);
	если (addr_and(a, a, &tmp_mask) == -1)
		вернуть (-1);
	вернуть (0);
}
#endif

целое
addr_host_to_all1s(struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_mask;

	если (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		вернуть (-1);
	если (addr_or(a, a, &tmp_mask) == -1)
		вернуть (-1);
	вернуть (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
целое
addr_pton(const char *p, struct xaddr *n)
{
	struct addrinfo hints, *ai;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	если (p == NULL || getaddrinfo(p, NULL, &hints, &ai) != 0)
		вернуть -1;

	если (ai == NULL)
		вернуть -1;

	если (ai->ai_addr == NULL) {
		freeaddrinfo(ai);
		вернуть -1;
	}

	если (n != NULL && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		вернуть -1;
	}

	freeaddrinfo(ai);
	вернуть 0;
}

#если 0
static целое
addr_sa_pton(const char *h, const char *s, struct sockaddr *sa, socklen_t slen)
{
	struct addrinfo hints, *ai;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	если (h == NULL || getaddrinfo(h, s, &hints, &ai) != 0)
		вернуть -1;

	если (ai == NULL)
		вернуть -1;

	если (ai->ai_addr == NULL) {
		freeaddrinfo(ai);
		вернуть -1;
	}

	если (sa != NULL) {
		если (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			вернуть -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	вернуть 0;
}
#endif

целое
addr_ntop(const struct xaddr *n, char *p, size_t len)
{
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);

	если (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		вернуть -1;
	если (p == NULL || len == 0)
		вернуть -1;
	если (getnameinfo(_SA(&ss), slen, p, len, NULL, 0,
	    NI_NUMERICHOST) != 0)
		вернуть -1;

	вернуть 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
целое
addr_pton_cidr(const char *p, struct xaddr *n, u_int *l)
{
	struct xaddr tmp;
	u_int masklen = 999;
	char addrbuf[64], *mp;
	const char *errstr;

	/* Don't modify argument */
	если (p == NULL || strlcpy(addrbuf, p, sizeof(addrbuf)) >= sizeof(addrbuf))
		вернуть -1;

	если ((mp = strchr(addrbuf, '/')) != NULL) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		если (errstr)
			вернуть -1;
	}

	если (addr_pton(addrbuf, &tmp) == -1)
		вернуть -1;

	если (mp == NULL)
		masklen = addr_unicast_masklen(tmp.af);
	если (masklen_valid(tmp.af, masklen) == -1)
		вернуть -2;
	если (addr_host_is_all0s(&tmp, masklen) != 0)
		вернуть -2;

	если (n != NULL)
		memcpy(n, &tmp, sizeof(*n));
	если (l != NULL)
		*l = masklen;

	вернуть 0;
}

целое
addr_netmatch(const struct xaddr *host, const struct xaddr *net, u_int masklen)
{
	struct xaddr tmp_mask, tmp_result;

	если (host->af != net->af)
		вернуть -1;

	если (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		вернуть -1;
	если (addr_and(&tmp_result, host, &tmp_mask) == -1)
		вернуть -1;
	вернуть addr_cmp(&tmp_result, net);
}
