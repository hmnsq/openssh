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

static цяло
addr_unicast_masklen(цяло af)
{
	switch (af) {
	case AF_INET:
		върни 32;
	case AF_INET6:
		върни 128;
	default:
		върни -1;
	}
}

static inline цяло
masklen_valid(цяло af, u_int masklen)
{
	switch (af) {
	case AF_INET:
		върни masklen <= 32 ? 0 : -1;
	case AF_INET6:
		върни masklen <= 128 ? 0 : -1;
	default:
		върни -1;
	}
}

static цяло
addr_xaddr_to_sa(const struct xaddr *xa, struct sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)sa;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;

	ако (xa == NULL || sa == NULL || len == NULL)
		върни -1;

	switch (xa->af) {
	case AF_INET:
		ако (*len < sizeof(*in4))
			върни -1;
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
		ако (*len < sizeof(*in6))
			върни -1;
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
		върни -1;
	}
	върни 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
цяло
addr_sa_to_xaddr(struct sockaddr *sa, socklen_t slen, struct xaddr *xa)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)sa;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;

	memset(xa, '\0', sizeof(*xa));

	switch (sa->sa_family) {
	case AF_INET:
		ако (slen < (socklen_t)sizeof(*in4))
			върни -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, sizeof(xa->v4));
		break;
	case AF_INET6:
		ако (slen < (socklen_t)sizeof(*in6))
			върни -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, sizeof(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		break;
	default:
		върни -1;
	}

	върни 0;
}

static цяло
addr_invert(struct xaddr *n)
{
	цяло i;

	ако (n == NULL)
		върни -1;

	switch (n->af) {
	case AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		върни 0;
	case AF_INET6:
		за (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		върни 0;
	default:
		върни -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
цяло
addr_netmask(цяло af, u_int l, struct xaddr *n)
{
	цяло i;

	ако (masklen_valid(af, l) != 0 || n == NULL)
		върни -1;

	memset(n, '\0', sizeof(*n));
	switch (af) {
	case AF_INET:
		n->af = AF_INET;
		ако (l == 0)
			върни 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		върни 0;
	case AF_INET6:
		n->af = AF_INET6;
		за (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		ако (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		върни 0;
	default:
		върни -1;
	}
}

static цяло
addr_hostmask(цяло af, u_int l, struct xaddr *n)
{
	ако (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		върни -1;
	върни 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
цяло
addr_and(struct xaddr *dst, const struct xaddr *a, const struct xaddr *b)
{
	цяло i;

	ако (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		върни -1;

	memcpy(dst, a, sizeof(*dst));
	switch (a->af) {
	case AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		върни 0;
	case AF_INET6:
		dst->scope_id = a->scope_id;
		за (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		върни 0;
	default:
		върни -1;
	}
}

static цяло
addr_or(struct xaddr *dst, const struct xaddr *a, const struct xaddr *b)
{
	цяло i;

	ако (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		върни (-1);

	memcpy(dst, a, sizeof(*dst));
	switch (a->af) {
	case AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		върни (0);
	case AF_INET6:
		за (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		върни (0);
	default:
		върни (-1);
	}
}

цяло
addr_cmp(const struct xaddr *a, const struct xaddr *b)
{
	цяло i;

	ако (a->af != b->af)
		върни (a->af == AF_INET6 ? 1 : -1);

	switch (a->af) {
	case AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		ако (a->v4.s_addr == b->v4.s_addr)
			върни 0;
		върни (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	case AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		за (i = 0; i < 16; i++)
			ако (a->addr8[i] - b->addr8[i] != 0)
				върни (a->addr8[i] - b->addr8[i]);
		ако (a->scope_id == b->scope_id)
			върни (0);
		върни (a->scope_id > b->scope_id ? 1 : -1);
	default:
		върни (-1);
	}
}

static цяло
addr_is_all0s(const struct xaddr *a)
{
	цяло i;

	switch (a->af) {
	case AF_INET:
		върни (a->v4.s_addr == 0 ? 0 : -1);
	case AF_INET6:
		за (i = 0; i < 4; i++)
			ако (a->addr32[i] != 0)
				върни -1;
		върни 0;
	default:
		върни -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
void
addr_increment(struct xaddr *a)
{
	цяло i;
	uint32_t n;

	switch (a->af) {
	case AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		break;
	case AF_INET6:
		за (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			ако (n != 0)
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
static цяло
addr_host_is_all0s(const struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, sizeof(tmp_addr));
	ако (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		върни -1;
	ако (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		върни -1;
	върни addr_is_all0s(&tmp_result);
}

#ако 0
static цяло
addr_host_to_all0s(struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_mask;

	ако (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		върни (-1);
	ако (addr_and(a, a, &tmp_mask) == -1)
		върни (-1);
	върни (0);
}
#endif

цяло
addr_host_to_all1s(struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_mask;

	ако (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		върни (-1);
	ако (addr_or(a, a, &tmp_mask) == -1)
		върни (-1);
	върни (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
цяло
addr_pton(const char *p, struct xaddr *n)
{
	struct addrinfo hints, *ai;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ако (p == NULL || getaddrinfo(p, NULL, &hints, &ai) != 0)
		върни -1;

	ако (ai == NULL)
		върни -1;

	ако (ai->ai_addr == NULL) {
		freeaddrinfo(ai);
		върни -1;
	}

	ако (n != NULL && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		върни -1;
	}

	freeaddrinfo(ai);
	върни 0;
}

#ако 0
static цяло
addr_sa_pton(const char *h, const char *s, struct sockaddr *sa, socklen_t slen)
{
	struct addrinfo hints, *ai;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ако (h == NULL || getaddrinfo(h, s, &hints, &ai) != 0)
		върни -1;

	ако (ai == NULL)
		върни -1;

	ако (ai->ai_addr == NULL) {
		freeaddrinfo(ai);
		върни -1;
	}

	ако (sa != NULL) {
		ако (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			върни -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	върни 0;
}
#endif

цяло
addr_ntop(const struct xaddr *n, char *p, size_t len)
{
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);

	ако (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		върни -1;
	ако (p == NULL || len == 0)
		върни -1;
	ако (getnameinfo(_SA(&ss), slen, p, len, NULL, 0,
	    NI_NUMERICHOST) != 0)
		върни -1;

	върни 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
цяло
addr_pton_cidr(const char *p, struct xaddr *n, u_int *l)
{
	struct xaddr tmp;
	u_int masklen = 999;
	char addrbuf[64], *mp;
	const char *errstr;

	/* Don't modify argument */
	ако (p == NULL || strlcpy(addrbuf, p, sizeof(addrbuf)) >= sizeof(addrbuf))
		върни -1;

	ако ((mp = strchr(addrbuf, '/')) != NULL) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		ако (errstr)
			върни -1;
	}

	ако (addr_pton(addrbuf, &tmp) == -1)
		върни -1;

	ако (mp == NULL)
		masklen = addr_unicast_masklen(tmp.af);
	ако (masklen_valid(tmp.af, masklen) == -1)
		върни -2;
	ако (addr_host_is_all0s(&tmp, masklen) != 0)
		върни -2;

	ако (n != NULL)
		memcpy(n, &tmp, sizeof(*n));
	ако (l != NULL)
		*l = masklen;

	върни 0;
}

цяло
addr_netmatch(const struct xaddr *host, const struct xaddr *net, u_int masklen)
{
	struct xaddr tmp_mask, tmp_result;

	ако (host->af != net->af)
		върни -1;

	ако (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		върни -1;
	ако (addr_and(&tmp_result, host, &tmp_mask) == -1)
		върни -1;
	върни addr_cmp(&tmp_result, net);
}
