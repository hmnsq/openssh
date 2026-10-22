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

static số_nguyên
addr_unicast_masklen(số_nguyên af)
{
	switch (af) {
	case AF_INET:
		trả_về 32;
	case AF_INET6:
		trả_về 128;
	default:
		trả_về -1;
	}
}

static inline số_nguyên
masklen_valid(số_nguyên af, u_int masklen)
{
	switch (af) {
	case AF_INET:
		trả_về masklen <= 32 ? 0 : -1;
	case AF_INET6:
		trả_về masklen <= 128 ? 0 : -1;
	default:
		trả_về -1;
	}
}

static số_nguyên
addr_xaddr_to_sa(const struct xaddr *xa, struct sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)sa;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;

	nếu (xa == NULL || sa == NULL || len == NULL)
		trả_về -1;

	switch (xa->af) {
	case AF_INET:
		nếu (*len < sizeof(*in4))
			trả_về -1;
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
		nếu (*len < sizeof(*in6))
			trả_về -1;
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
		trả_về -1;
	}
	trả_về 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
số_nguyên
addr_sa_to_xaddr(struct sockaddr *sa, socklen_t slen, struct xaddr *xa)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)sa;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;

	memset(xa, '\0', sizeof(*xa));

	switch (sa->sa_family) {
	case AF_INET:
		nếu (slen < (socklen_t)sizeof(*in4))
			trả_về -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, sizeof(xa->v4));
		break;
	case AF_INET6:
		nếu (slen < (socklen_t)sizeof(*in6))
			trả_về -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, sizeof(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		break;
	default:
		trả_về -1;
	}

	trả_về 0;
}

static số_nguyên
addr_invert(struct xaddr *n)
{
	số_nguyên i;

	nếu (n == NULL)
		trả_về -1;

	switch (n->af) {
	case AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		trả_về 0;
	case AF_INET6:
		cho (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		trả_về 0;
	default:
		trả_về -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
số_nguyên
addr_netmask(số_nguyên af, u_int l, struct xaddr *n)
{
	số_nguyên i;

	nếu (masklen_valid(af, l) != 0 || n == NULL)
		trả_về -1;

	memset(n, '\0', sizeof(*n));
	switch (af) {
	case AF_INET:
		n->af = AF_INET;
		nếu (l == 0)
			trả_về 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		trả_về 0;
	case AF_INET6:
		n->af = AF_INET6;
		cho (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		nếu (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		trả_về 0;
	default:
		trả_về -1;
	}
}

static số_nguyên
addr_hostmask(số_nguyên af, u_int l, struct xaddr *n)
{
	nếu (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		trả_về -1;
	trả_về 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
số_nguyên
addr_and(struct xaddr *dst, const struct xaddr *a, const struct xaddr *b)
{
	số_nguyên i;

	nếu (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		trả_về -1;

	memcpy(dst, a, sizeof(*dst));
	switch (a->af) {
	case AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		trả_về 0;
	case AF_INET6:
		dst->scope_id = a->scope_id;
		cho (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		trả_về 0;
	default:
		trả_về -1;
	}
}

static số_nguyên
addr_or(struct xaddr *dst, const struct xaddr *a, const struct xaddr *b)
{
	số_nguyên i;

	nếu (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		trả_về (-1);

	memcpy(dst, a, sizeof(*dst));
	switch (a->af) {
	case AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		trả_về (0);
	case AF_INET6:
		cho (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		trả_về (0);
	default:
		trả_về (-1);
	}
}

số_nguyên
addr_cmp(const struct xaddr *a, const struct xaddr *b)
{
	số_nguyên i;

	nếu (a->af != b->af)
		trả_về (a->af == AF_INET6 ? 1 : -1);

	switch (a->af) {
	case AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		nếu (a->v4.s_addr == b->v4.s_addr)
			trả_về 0;
		trả_về (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	case AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		cho (i = 0; i < 16; i++)
			nếu (a->addr8[i] - b->addr8[i] != 0)
				trả_về (a->addr8[i] - b->addr8[i]);
		nếu (a->scope_id == b->scope_id)
			trả_về (0);
		trả_về (a->scope_id > b->scope_id ? 1 : -1);
	default:
		trả_về (-1);
	}
}

static số_nguyên
addr_is_all0s(const struct xaddr *a)
{
	số_nguyên i;

	switch (a->af) {
	case AF_INET:
		trả_về (a->v4.s_addr == 0 ? 0 : -1);
	case AF_INET6:
		cho (i = 0; i < 4; i++)
			nếu (a->addr32[i] != 0)
				trả_về -1;
		trả_về 0;
	default:
		trả_về -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
void
addr_increment(struct xaddr *a)
{
	số_nguyên i;
	uint32_t n;

	switch (a->af) {
	case AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		break;
	case AF_INET6:
		cho (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			nếu (n != 0)
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
static số_nguyên
addr_host_is_all0s(const struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, sizeof(tmp_addr));
	nếu (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		trả_về -1;
	nếu (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		trả_về -1;
	trả_về addr_is_all0s(&tmp_result);
}

#nếu 0
static số_nguyên
addr_host_to_all0s(struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_mask;

	nếu (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		trả_về (-1);
	nếu (addr_and(a, a, &tmp_mask) == -1)
		trả_về (-1);
	trả_về (0);
}
#endif

số_nguyên
addr_host_to_all1s(struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_mask;

	nếu (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		trả_về (-1);
	nếu (addr_or(a, a, &tmp_mask) == -1)
		trả_về (-1);
	trả_về (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
số_nguyên
addr_pton(const char *p, struct xaddr *n)
{
	struct addrinfo hints, *ai;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	nếu (p == NULL || getaddrinfo(p, NULL, &hints, &ai) != 0)
		trả_về -1;

	nếu (ai == NULL)
		trả_về -1;

	nếu (ai->ai_addr == NULL) {
		freeaddrinfo(ai);
		trả_về -1;
	}

	nếu (n != NULL && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		trả_về -1;
	}

	freeaddrinfo(ai);
	trả_về 0;
}

#nếu 0
static số_nguyên
addr_sa_pton(const char *h, const char *s, struct sockaddr *sa, socklen_t slen)
{
	struct addrinfo hints, *ai;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	nếu (h == NULL || getaddrinfo(h, s, &hints, &ai) != 0)
		trả_về -1;

	nếu (ai == NULL)
		trả_về -1;

	nếu (ai->ai_addr == NULL) {
		freeaddrinfo(ai);
		trả_về -1;
	}

	nếu (sa != NULL) {
		nếu (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			trả_về -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	trả_về 0;
}
#endif

số_nguyên
addr_ntop(const struct xaddr *n, char *p, size_t len)
{
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);

	nếu (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		trả_về -1;
	nếu (p == NULL || len == 0)
		trả_về -1;
	nếu (getnameinfo(_SA(&ss), slen, p, len, NULL, 0,
	    NI_NUMERICHOST) != 0)
		trả_về -1;

	trả_về 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
số_nguyên
addr_pton_cidr(const char *p, struct xaddr *n, u_int *l)
{
	struct xaddr tmp;
	u_int masklen = 999;
	char addrbuf[64], *mp;
	const char *errstr;

	/* Don't modify argument */
	nếu (p == NULL || strlcpy(addrbuf, p, sizeof(addrbuf)) >= sizeof(addrbuf))
		trả_về -1;

	nếu ((mp = strchr(addrbuf, '/')) != NULL) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		nếu (errstr)
			trả_về -1;
	}

	nếu (addr_pton(addrbuf, &tmp) == -1)
		trả_về -1;

	nếu (mp == NULL)
		masklen = addr_unicast_masklen(tmp.af);
	nếu (masklen_valid(tmp.af, masklen) == -1)
		trả_về -2;
	nếu (addr_host_is_all0s(&tmp, masklen) != 0)
		trả_về -2;

	nếu (n != NULL)
		memcpy(n, &tmp, sizeof(*n));
	nếu (l != NULL)
		*l = masklen;

	trả_về 0;
}

số_nguyên
addr_netmatch(const struct xaddr *host, const struct xaddr *net, u_int masklen)
{
	struct xaddr tmp_mask, tmp_result;

	nếu (host->af != net->af)
		trả_về -1;

	nếu (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		trả_về -1;
	nếu (addr_and(&tmp_result, host, &tmp_mask) == -1)
		trả_về -1;
	trả_về addr_cmp(&tmp_result, net);
}
