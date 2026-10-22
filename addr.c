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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <arpa/inet.h>

#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ "addr.h"

#define _SA(x)	((સંરચના sockaddr *)(x))

સ્થિર પૂર્ણાંક
addr_unicast_masklen(પૂર્ણાંક af)
{
	પસંદગી (af) {
	સ્થિતિ AF_INET:
		પાછા 32;
	સ્થિતિ AF_INET6:
		પાછા 128;
	મૂળભૂત:
		પાછા -1;
	}
}

સ્થિર અંતઃરેખ પૂર્ણાંક
masklen_valid(પૂર્ણાંક af, u_int masklen)
{
	પસંદગી (af) {
	સ્થિતિ AF_INET:
		પાછા masklen <= 32 ? 0 : -1;
	સ્થિતિ AF_INET6:
		પાછા masklen <= 128 ? 0 : -1;
	મૂળભૂત:
		પાછા -1;
	}
}

સ્થિર પૂર્ણાંક
addr_xaddr_to_sa(અચલ સંરચના xaddr *xa, સંરચના sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	સંરચના sockaddr_in *in4 = (સંરચના sockaddr_in *)sa;
	સંરચના sockaddr_in6 *in6 = (સંરચના sockaddr_in6 *)sa;

	જો (xa == ખાલી || sa == ખાલી || len == ખાલી)
		પાછા -1;

	પસંદગી (xa->af) {
	સ્થિતિ AF_INET:
		જો (*len < કદ(*in4))
			પાછા -1;
		memset(sa, '\0', કદ(*in4));
		*len = કદ(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = કદ(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, કદ(in4->sin_addr));
		તોડો;
	સ્થિતિ AF_INET6:
		જો (*len < કદ(*in6))
			પાછા -1;
		memset(sa, '\0', કદ(*in6));
		*len = કદ(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = કદ(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, કદ(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		તોડો;
	મૂળભૂત:
		પાછા -1;
	}
	પાછા 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
પૂર્ણાંક
addr_sa_to_xaddr(સંરચના sockaddr *sa, socklen_t slen, સંરચના xaddr *xa)
{
	સંરચના sockaddr_in *in4 = (સંરચના sockaddr_in *)sa;
	સંરચના sockaddr_in6 *in6 = (સંરચના sockaddr_in6 *)sa;

	memset(xa, '\0', કદ(*xa));

	પસંદગી (sa->sa_family) {
	સ્થિતિ AF_INET:
		જો (slen < (socklen_t)કદ(*in4))
			પાછા -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, કદ(xa->v4));
		તોડો;
	સ્થિતિ AF_INET6:
		જો (slen < (socklen_t)કદ(*in6))
			પાછા -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, કદ(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		તોડો;
	મૂળભૂત:
		પાછા -1;
	}

	પાછા 0;
}

સ્થિર પૂર્ણાંક
addr_invert(સંરચના xaddr *n)
{
	પૂર્ણાંક i;

	જો (n == ખાલી)
		પાછા -1;

	પસંદગી (n->af) {
	સ્થિતિ AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		પાછા 0;
	સ્થિતિ AF_INET6:
		માટે (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		પાછા 0;
	મૂળભૂત:
		પાછા -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
પૂર્ણાંક
addr_netmask(પૂર્ણાંક af, u_int l, સંરચના xaddr *n)
{
	પૂર્ણાંક i;

	જો (masklen_valid(af, l) != 0 || n == ખાલી)
		પાછા -1;

	memset(n, '\0', કદ(*n));
	પસંદગી (af) {
	સ્થિતિ AF_INET:
		n->af = AF_INET;
		જો (l == 0)
			પાછા 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		પાછા 0;
	સ્થિતિ AF_INET6:
		n->af = AF_INET6;
		માટે (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		જો (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		પાછા 0;
	મૂળભૂત:
		પાછા -1;
	}
}

સ્થિર પૂર્ણાંક
addr_hostmask(પૂર્ણાંક af, u_int l, સંરચના xaddr *n)
{
	જો (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		પાછા -1;
	પાછા 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
પૂર્ણાંક
addr_and(સંરચના xaddr *dst, અચલ સંરચના xaddr *a, અચલ સંરચના xaddr *b)
{
	પૂર્ણાંક i;

	જો (dst == ખાલી || a == ખાલી || b == ખાલી || a->af != b->af)
		પાછા -1;

	memcpy(dst, a, કદ(*dst));
	પસંદગી (a->af) {
	સ્થિતિ AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		પાછા 0;
	સ્થિતિ AF_INET6:
		dst->scope_id = a->scope_id;
		માટે (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		પાછા 0;
	મૂળભૂત:
		પાછા -1;
	}
}

સ્થિર પૂર્ણાંક
addr_or(સંરચના xaddr *dst, અચલ સંરચના xaddr *a, અચલ સંરચના xaddr *b)
{
	પૂર્ણાંક i;

	જો (dst == ખાલી || a == ખાલી || b == ખાલી || a->af != b->af)
		પાછા (-1);

	memcpy(dst, a, કદ(*dst));
	પસંદગી (a->af) {
	સ્થિતિ AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		પાછા (0);
	સ્થિતિ AF_INET6:
		માટે (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		પાછા (0);
	મૂળભૂત:
		પાછા (-1);
	}
}

પૂર્ણાંક
addr_cmp(અચલ સંરચના xaddr *a, અચલ સંરચના xaddr *b)
{
	પૂર્ણાંક i;

	જો (a->af != b->af)
		પાછા (a->af == AF_INET6 ? 1 : -1);

	પસંદગી (a->af) {
	સ્થિતિ AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		જો (a->v4.s_addr == b->v4.s_addr)
			પાછા 0;
		પાછા (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	સ્થિતિ AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		માટે (i = 0; i < 16; i++)
			જો (a->addr8[i] - b->addr8[i] != 0)
				પાછા (a->addr8[i] - b->addr8[i]);
		જો (a->scope_id == b->scope_id)
			પાછા (0);
		પાછા (a->scope_id > b->scope_id ? 1 : -1);
	મૂળભૂત:
		પાછા (-1);
	}
}

સ્થિર પૂર્ણાંક
addr_is_all0s(અચલ સંરચના xaddr *a)
{
	પૂર્ણાંક i;

	પસંદગી (a->af) {
	સ્થિતિ AF_INET:
		પાછા (a->v4.s_addr == 0 ? 0 : -1);
	સ્થિતિ AF_INET6:
		માટે (i = 0; i < 4; i++)
			જો (a->addr32[i] != 0)
				પાછા -1;
		પાછા 0;
	મૂળભૂત:
		પાછા -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
શૂન્ય
addr_increment(સંરચના xaddr *a)
{
	પૂર્ણાંક i;
	uint32_t n;

	પસંદગી (a->af) {
	સ્થિતિ AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		તોડો;
	સ્થિતિ AF_INET6:
		માટે (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			જો (n != 0)
				તોડો;
		}
		તોડો;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
સ્થિર પૂર્ણાંક
addr_host_is_all0s(અચલ સંરચના xaddr *a, u_int masklen)
{
	સંરચના xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, કદ(tmp_addr));
	જો (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		પાછા -1;
	જો (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		પાછા -1;
	પાછા addr_is_all0s(&tmp_result);
}

#જો 0
સ્થિર પૂર્ણાંક
addr_host_to_all0s(સંરચના xaddr *a, u_int masklen)
{
	સંરચના xaddr tmp_mask;

	જો (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		પાછા (-1);
	જો (addr_and(a, a, &tmp_mask) == -1)
		પાછા (-1);
	પાછા (0);
}
#endif

પૂર્ણાંક
addr_host_to_all1s(સંરચના xaddr *a, u_int masklen)
{
	સંરચના xaddr tmp_mask;

	જો (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		પાછા (-1);
	જો (addr_or(a, a, &tmp_mask) == -1)
		પાછા (-1);
	પાછા (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
પૂર્ણાંક
addr_pton(અચલ અક્ષર *p, સંરચના xaddr *n)
{
	સંરચના addrinfo hints, *ai;

	memset(&hints, '\0', કદ(hints));
	hints.ai_flags = AI_NUMERICHOST;

	જો (p == ખાલી || getaddrinfo(p, ખાલી, &hints, &ai) != 0)
		પાછા -1;

	જો (ai == ખાલી)
		પાછા -1;

	જો (ai->ai_addr == ખાલી) {
		freeaddrinfo(ai);
		પાછા -1;
	}

	જો (n != ખાલી && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		પાછા -1;
	}

	freeaddrinfo(ai);
	પાછા 0;
}

#જો 0
સ્થિર પૂર્ણાંક
addr_sa_pton(અચલ અક્ષર *h, અચલ અક્ષર *s, સંરચના sockaddr *sa, socklen_t slen)
{
	સંરચના addrinfo hints, *ai;

	memset(&hints, '\0', કદ(hints));
	hints.ai_flags = AI_NUMERICHOST;

	જો (h == ખાલી || getaddrinfo(h, s, &hints, &ai) != 0)
		પાછા -1;

	જો (ai == ખાલી)
		પાછા -1;

	જો (ai->ai_addr == ખાલી) {
		freeaddrinfo(ai);
		પાછા -1;
	}

	જો (sa != ખાલી) {
		જો (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			પાછા -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	પાછા 0;
}
#endif

પૂર્ણાંક
addr_ntop(અચલ સંરચના xaddr *n, અક્ષર *p, size_t len)
{
	સંરચના sockaddr_storage ss;
	socklen_t slen = કદ(ss);

	જો (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		પાછા -1;
	જો (p == ખાલી || len == 0)
		પાછા -1;
	જો (getnameinfo(_SA(&ss), slen, p, len, ખાલી, 0,
	    NI_NUMERICHOST) != 0)
		પાછા -1;

	પાછા 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
પૂર્ણાંક
addr_pton_cidr(અચલ અક્ષર *p, સંરચના xaddr *n, u_int *l)
{
	સંરચના xaddr tmp;
	u_int masklen = 999;
	અક્ષર addrbuf[64], *mp;
	અચલ અક્ષર *errstr;

	/* Don't modify argument */
	જો (p == ખાલી || strlcpy(addrbuf, p, કદ(addrbuf)) >= કદ(addrbuf))
		પાછા -1;

	જો ((mp = strchr(addrbuf, '/')) != ખાલી) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		જો (errstr)
			પાછા -1;
	}

	જો (addr_pton(addrbuf, &tmp) == -1)
		પાછા -1;

	જો (mp == ખાલી)
		masklen = addr_unicast_masklen(tmp.af);
	જો (masklen_valid(tmp.af, masklen) == -1)
		પાછા -2;
	જો (addr_host_is_all0s(&tmp, masklen) != 0)
		પાછા -2;

	જો (n != ખાલી)
		memcpy(n, &tmp, કદ(*n));
	જો (l != ખાલી)
		*l = masklen;

	પાછા 0;
}

પૂર્ણાંક
addr_netmatch(અચલ સંરચના xaddr *host, અચલ સંરચના xaddr *net, u_int masklen)
{
	સંરચના xaddr tmp_mask, tmp_result;

	જો (host->af != net->af)
		પાછા -1;

	જો (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		પાછા -1;
	જો (addr_and(&tmp_result, host, &tmp_mask) == -1)
		પાછા -1;
	પાછા addr_cmp(&tmp_result, net);
}
