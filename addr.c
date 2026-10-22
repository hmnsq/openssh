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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <netinet/in.h>
#অন্তর্ভাৱ <arpa/inet.h>

#অন্তর্ভাৱ <netdb.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <limits.h>

#অন্তর্ভাৱ "addr.h"

#define _SA(x)	((সংরচনা sockaddr *)(x))

স্থির পূর্ণাঙ্ক
addr_unicast_masklen(পূর্ণাঙ্ক af)
{
	ৱিকল্প (af) {
	পক্ষ AF_INET:
		ঘূৰাই 32;
	পক্ষ AF_INET6:
		ঘূৰাই 128;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

স্থির অন্তঃস্থ পূর্ণাঙ্ক
masklen_valid(পূর্ণাঙ্ক af, u_int masklen)
{
	ৱিকল্প (af) {
	পক্ষ AF_INET:
		ঘূৰাই masklen <= 32 ? 0 : -1;
	পক্ষ AF_INET6:
		ঘূৰাই masklen <= 128 ? 0 : -1;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

স্থির পূর্ণাঙ্ক
addr_xaddr_to_sa(ধ্রুৱ সংরচনা xaddr *xa, সংরচনা sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	সংরচনা sockaddr_in *in4 = (সংরচনা sockaddr_in *)sa;
	সংরচনা sockaddr_in6 *in6 = (সংরচনা sockaddr_in6 *)sa;

	যদি (xa == রিক্ত || sa == রিক্ত || len == রিক্ত)
		ঘূৰাই -1;

	ৱিকল্প (xa->af) {
	পক্ষ AF_INET:
		যদি (*len < পরিমাণ(*in4))
			ঘূৰাই -1;
		memset(sa, '\0', পরিমাণ(*in4));
		*len = পরিমাণ(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = পরিমাণ(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, পরিমাণ(in4->sin_addr));
		ভঙ্গ;
	পক্ষ AF_INET6:
		যদি (*len < পরিমাণ(*in6))
			ঘূৰাই -1;
		memset(sa, '\0', পরিমাণ(*in6));
		*len = পরিমাণ(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = পরিমাণ(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, পরিমাণ(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		ভঙ্গ;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
	ঘূৰাই 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
পূর্ণাঙ্ক
addr_sa_to_xaddr(সংরচনা sockaddr *sa, socklen_t slen, সংরচনা xaddr *xa)
{
	সংরচনা sockaddr_in *in4 = (সংরচনা sockaddr_in *)sa;
	সংরচনা sockaddr_in6 *in6 = (সংরচনা sockaddr_in6 *)sa;

	memset(xa, '\0', পরিমাণ(*xa));

	ৱিকল্প (sa->sa_family) {
	পক্ষ AF_INET:
		যদি (slen < (socklen_t)পরিমাণ(*in4))
			ঘূৰাই -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, পরিমাণ(xa->v4));
		ভঙ্গ;
	পক্ষ AF_INET6:
		যদি (slen < (socklen_t)পরিমাণ(*in6))
			ঘূৰাই -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, পরিমাণ(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		ভঙ্গ;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}

	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
addr_invert(সংরচনা xaddr *n)
{
	পূর্ণাঙ্ক i;

	যদি (n == রিক্ত)
		ঘূৰাই -1;

	ৱিকল্প (n->af) {
	পক্ষ AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		ঘূৰাই 0;
	পক্ষ AF_INET6:
		বাবে (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		ঘূৰাই 0;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
পূর্ণাঙ্ক
addr_netmask(পূর্ণাঙ্ক af, u_int l, সংরচনা xaddr *n)
{
	পূর্ণাঙ্ক i;

	যদি (masklen_valid(af, l) != 0 || n == রিক্ত)
		ঘূৰাই -1;

	memset(n, '\0', পরিমাণ(*n));
	ৱিকল্প (af) {
	পক্ষ AF_INET:
		n->af = AF_INET;
		যদি (l == 0)
			ঘূৰাই 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		ঘূৰাই 0;
	পক্ষ AF_INET6:
		n->af = AF_INET6;
		বাবে (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		যদি (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		ঘূৰাই 0;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

স্থির পূর্ণাঙ্ক
addr_hostmask(পূর্ণাঙ্ক af, u_int l, সংরচনা xaddr *n)
{
	যদি (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		ঘূৰাই -1;
	ঘূৰাই 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
পূর্ণাঙ্ক
addr_and(সংরচনা xaddr *dst, ধ্রুৱ সংরচনা xaddr *a, ধ্রুৱ সংরচনা xaddr *b)
{
	পূর্ণাঙ্ক i;

	যদি (dst == রিক্ত || a == রিক্ত || b == রিক্ত || a->af != b->af)
		ঘূৰাই -1;

	memcpy(dst, a, পরিমাণ(*dst));
	ৱিকল্প (a->af) {
	পক্ষ AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		ঘূৰাই 0;
	পক্ষ AF_INET6:
		dst->scope_id = a->scope_id;
		বাবে (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		ঘূৰাই 0;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

স্থির পূর্ণাঙ্ক
addr_or(সংরচনা xaddr *dst, ধ্রুৱ সংরচনা xaddr *a, ধ্রুৱ সংরচনা xaddr *b)
{
	পূর্ণাঙ্ক i;

	যদি (dst == রিক্ত || a == রিক্ত || b == রিক্ত || a->af != b->af)
		ঘূৰাই (-1);

	memcpy(dst, a, পরিমাণ(*dst));
	ৱিকল্প (a->af) {
	পক্ষ AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		ঘূৰাই (0);
	পক্ষ AF_INET6:
		বাবে (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		ঘূৰাই (0);
	স্ৱভাৱ:
		ঘূৰাই (-1);
	}
}

পূর্ণাঙ্ক
addr_cmp(ধ্রুৱ সংরচনা xaddr *a, ধ্রুৱ সংরচনা xaddr *b)
{
	পূর্ণাঙ্ক i;

	যদি (a->af != b->af)
		ঘূৰাই (a->af == AF_INET6 ? 1 : -1);

	ৱিকল্প (a->af) {
	পক্ষ AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		যদি (a->v4.s_addr == b->v4.s_addr)
			ঘূৰাই 0;
		ঘূৰাই (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	পক্ষ AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		বাবে (i = 0; i < 16; i++)
			যদি (a->addr8[i] - b->addr8[i] != 0)
				ঘূৰাই (a->addr8[i] - b->addr8[i]);
		যদি (a->scope_id == b->scope_id)
			ঘূৰাই (0);
		ঘূৰাই (a->scope_id > b->scope_id ? 1 : -1);
	স্ৱভাৱ:
		ঘূৰাই (-1);
	}
}

স্থির পূর্ণাঙ্ক
addr_is_all0s(ধ্রুৱ সংরচনা xaddr *a)
{
	পূর্ণাঙ্ক i;

	ৱিকল্প (a->af) {
	পক্ষ AF_INET:
		ঘূৰাই (a->v4.s_addr == 0 ? 0 : -1);
	পক্ষ AF_INET6:
		বাবে (i = 0; i < 4; i++)
			যদি (a->addr32[i] != 0)
				ঘূৰাই -1;
		ঘূৰাই 0;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
শূন্য
addr_increment(সংরচনা xaddr *a)
{
	পূর্ণাঙ্ক i;
	uint32_t n;

	ৱিকল্প (a->af) {
	পক্ষ AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		ভঙ্গ;
	পক্ষ AF_INET6:
		বাবে (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			যদি (n != 0)
				ভঙ্গ;
		}
		ভঙ্গ;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
স্থির পূর্ণাঙ্ক
addr_host_is_all0s(ধ্রুৱ সংরচনা xaddr *a, u_int masklen)
{
	সংরচনা xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, পরিমাণ(tmp_addr));
	যদি (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ঘূৰাই -1;
	যদি (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		ঘূৰাই -1;
	ঘূৰাই addr_is_all0s(&tmp_result);
}

#যদি 0
স্থির পূর্ণাঙ্ক
addr_host_to_all0s(সংরচনা xaddr *a, u_int masklen)
{
	সংরচনা xaddr tmp_mask;

	যদি (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		ঘূৰাই (-1);
	যদি (addr_and(a, a, &tmp_mask) == -1)
		ঘূৰাই (-1);
	ঘূৰাই (0);
}
#endif

পূর্ণাঙ্ক
addr_host_to_all1s(সংরচনা xaddr *a, u_int masklen)
{
	সংরচনা xaddr tmp_mask;

	যদি (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ঘূৰাই (-1);
	যদি (addr_or(a, a, &tmp_mask) == -1)
		ঘূৰাই (-1);
	ঘূৰাই (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
পূর্ণাঙ্ক
addr_pton(ধ্রুৱ ৱর্ণ *p, সংরচনা xaddr *n)
{
	সংরচনা addrinfo hints, *ai;

	memset(&hints, '\0', পরিমাণ(hints));
	hints.ai_flags = AI_NUMERICHOST;

	যদি (p == রিক্ত || getaddrinfo(p, রিক্ত, &hints, &ai) != 0)
		ঘূৰাই -1;

	যদি (ai == রিক্ত)
		ঘূৰাই -1;

	যদি (ai->ai_addr == রিক্ত) {
		freeaddrinfo(ai);
		ঘূৰাই -1;
	}

	যদি (n != রিক্ত && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		ঘূৰাই -1;
	}

	freeaddrinfo(ai);
	ঘূৰাই 0;
}

#যদি 0
স্থির পূর্ণাঙ্ক
addr_sa_pton(ধ্রুৱ ৱর্ণ *h, ধ্রুৱ ৱর্ণ *s, সংরচনা sockaddr *sa, socklen_t slen)
{
	সংরচনা addrinfo hints, *ai;

	memset(&hints, '\0', পরিমাণ(hints));
	hints.ai_flags = AI_NUMERICHOST;

	যদি (h == রিক্ত || getaddrinfo(h, s, &hints, &ai) != 0)
		ঘূৰাই -1;

	যদি (ai == রিক্ত)
		ঘূৰাই -1;

	যদি (ai->ai_addr == রিক্ত) {
		freeaddrinfo(ai);
		ঘূৰাই -1;
	}

	যদি (sa != রিক্ত) {
		যদি (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			ঘূৰাই -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	ঘূৰাই 0;
}
#endif

পূর্ণাঙ্ক
addr_ntop(ধ্রুৱ সংরচনা xaddr *n, ৱর্ণ *p, size_t len)
{
	সংরচনা sockaddr_storage ss;
	socklen_t slen = পরিমাণ(ss);

	যদি (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		ঘূৰাই -1;
	যদি (p == রিক্ত || len == 0)
		ঘূৰাই -1;
	যদি (getnameinfo(_SA(&ss), slen, p, len, রিক্ত, 0,
	    NI_NUMERICHOST) != 0)
		ঘূৰাই -1;

	ঘূৰাই 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
পূর্ণাঙ্ক
addr_pton_cidr(ধ্রুৱ ৱর্ণ *p, সংরচনা xaddr *n, u_int *l)
{
	সংরচনা xaddr tmp;
	u_int masklen = 999;
	ৱর্ণ addrbuf[64], *mp;
	ধ্রুৱ ৱর্ণ *errstr;

	/* Don't modify argument */
	যদি (p == রিক্ত || strlcpy(addrbuf, p, পরিমাণ(addrbuf)) >= পরিমাণ(addrbuf))
		ঘূৰাই -1;

	যদি ((mp = strchr(addrbuf, '/')) != রিক্ত) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		যদি (errstr)
			ঘূৰাই -1;
	}

	যদি (addr_pton(addrbuf, &tmp) == -1)
		ঘূৰাই -1;

	যদি (mp == রিক্ত)
		masklen = addr_unicast_masklen(tmp.af);
	যদি (masklen_valid(tmp.af, masklen) == -1)
		ঘূৰাই -2;
	যদি (addr_host_is_all0s(&tmp, masklen) != 0)
		ঘূৰাই -2;

	যদি (n != রিক্ত)
		memcpy(n, &tmp, পরিমাণ(*n));
	যদি (l != রিক্ত)
		*l = masklen;

	ঘূৰাই 0;
}

পূর্ণাঙ্ক
addr_netmatch(ধ্রুৱ সংরচনা xaddr *host, ধ্রুৱ সংরচনা xaddr *net, u_int masklen)
{
	সংরচনা xaddr tmp_mask, tmp_result;

	যদি (host->af != net->af)
		ঘূৰাই -1;

	যদি (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		ঘূৰাই -1;
	যদি (addr_and(&tmp_result, host, &tmp_mask) == -1)
		ঘূৰাই -1;
	ঘূৰাই addr_cmp(&tmp_result, net);
}
