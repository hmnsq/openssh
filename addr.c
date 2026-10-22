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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ଅନ୍ତର୍ଭାଵ "addr.h"

#define _SA(x)	((ସଂରଚନା sockaddr *)(x))

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_unicast_masklen(ପୂର୍ଣ୍ଣସଂଖ୍ୟା af)
{
	ବାଛ (af) {
	ସ୍ଥିତି AF_INET:
		ଫେରନ୍ତୁ 32;
	ସ୍ଥିତି AF_INET6:
		ଫେରନ୍ତୁ 128;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ପୂର୍ଣ୍ଣସଂଖ୍ୟା
masklen_valid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା af, u_int masklen)
{
	ବାଛ (af) {
	ସ୍ଥିତି AF_INET:
		ଫେରନ୍ତୁ masklen <= 32 ? 0 : -1;
	ସ୍ଥିତି AF_INET6:
		ଫେରନ୍ତୁ masklen <= 128 ? 0 : -1;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_xaddr_to_sa(ଅଚଳ ସଂରଚନା xaddr *xa, ସଂରଚନା sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	ସଂରଚନା sockaddr_in *in4 = (ସଂରଚନା sockaddr_in *)sa;
	ସଂରଚନା sockaddr_in6 *in6 = (ସଂରଚନା sockaddr_in6 *)sa;

	ଯଦି (xa == ଖାଲି || sa == ଖାଲି || len == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	ବାଛ (xa->af) {
	ସ୍ଥିତି AF_INET:
		ଯଦି (*len < ଆକାର(*in4))
			ଫେରନ୍ତୁ -1;
		memset(sa, '\0', ଆକାର(*in4));
		*len = ଆକାର(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = ଆକାର(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, ଆକାର(in4->sin_addr));
		ଭାଙ୍ଗ;
	ସ୍ଥିତି AF_INET6:
		ଯଦି (*len < ଆକାର(*in6))
			ଫେରନ୍ତୁ -1;
		memset(sa, '\0', ଆକାର(*in6));
		*len = ଆକାର(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = ଆକାର(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, ଆକାର(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_sa_to_xaddr(ସଂରଚନା sockaddr *sa, socklen_t slen, ସଂରଚନା xaddr *xa)
{
	ସଂରଚନା sockaddr_in *in4 = (ସଂରଚନା sockaddr_in *)sa;
	ସଂରଚନା sockaddr_in6 *in6 = (ସଂରଚନା sockaddr_in6 *)sa;

	memset(xa, '\0', ଆକାର(*xa));

	ବାଛ (sa->sa_family) {
	ସ୍ଥିତି AF_INET:
		ଯଦି (slen < (socklen_t)ଆକାର(*in4))
			ଫେରନ୍ତୁ -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, ଆକାର(xa->v4));
		ଭାଙ୍ଗ;
	ସ୍ଥିତି AF_INET6:
		ଯଦି (slen < (socklen_t)ଆକାର(*in6))
			ଫେରନ୍ତୁ -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, ଆକାର(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_invert(ସଂରଚନା xaddr *n)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (n == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	ବାଛ (n->af) {
	ସ୍ଥିତି AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି AF_INET6:
		ପାଇଁ (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		ଫେରନ୍ତୁ 0;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_netmask(ପୂର୍ଣ୍ଣସଂଖ୍ୟା af, u_int l, ସଂରଚନା xaddr *n)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (masklen_valid(af, l) != 0 || n == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	memset(n, '\0', ଆକାର(*n));
	ବାଛ (af) {
	ସ୍ଥିତି AF_INET:
		n->af = AF_INET;
		ଯଦି (l == 0)
			ଫେରନ୍ତୁ 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି AF_INET6:
		n->af = AF_INET6;
		ପାଇଁ (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		ଯଦି (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		ଫେରନ୍ତୁ 0;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_hostmask(ପୂର୍ଣ୍ଣସଂଖ୍ୟା af, u_int l, ସଂରଚନା xaddr *n)
{
	ଯଦି (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_and(ସଂରଚନା xaddr *dst, ଅଚଳ ସଂରଚନା xaddr *a, ଅଚଳ ସଂରଚନା xaddr *b)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (dst == ଖାଲି || a == ଖାଲି || b == ଖାଲି || a->af != b->af)
		ଫେରନ୍ତୁ -1;

	memcpy(dst, a, ଆକାର(*dst));
	ବାଛ (a->af) {
	ସ୍ଥିତି AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି AF_INET6:
		dst->scope_id = a->scope_id;
		ପାଇଁ (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		ଫେରନ୍ତୁ 0;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_or(ସଂରଚନା xaddr *dst, ଅଚଳ ସଂରଚନା xaddr *a, ଅଚଳ ସଂରଚନା xaddr *b)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (dst == ଖାଲି || a == ଖାଲି || b == ଖାଲି || a->af != b->af)
		ଫେରନ୍ତୁ (-1);

	memcpy(dst, a, ଆକାର(*dst));
	ବାଛ (a->af) {
	ସ୍ଥିତି AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		ଫେରନ୍ତୁ (0);
	ସ୍ଥିତି AF_INET6:
		ପାଇଁ (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		ଫେରନ୍ତୁ (0);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ (-1);
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_cmp(ଅଚଳ ସଂରଚନା xaddr *a, ଅଚଳ ସଂରଚନା xaddr *b)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (a->af != b->af)
		ଫେରନ୍ତୁ (a->af == AF_INET6 ? 1 : -1);

	ବାଛ (a->af) {
	ସ୍ଥିତି AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		ଯଦି (a->v4.s_addr == b->v4.s_addr)
			ଫେରନ୍ତୁ 0;
		ଫେରନ୍ତୁ (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	ସ୍ଥିତି AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		ପାଇଁ (i = 0; i < 16; i++)
			ଯଦି (a->addr8[i] - b->addr8[i] != 0)
				ଫେରନ୍ତୁ (a->addr8[i] - b->addr8[i]);
		ଯଦି (a->scope_id == b->scope_id)
			ଫେରନ୍ତୁ (0);
		ଫେରନ୍ତୁ (a->scope_id > b->scope_id ? 1 : -1);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ (-1);
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_is_all0s(ଅଚଳ ସଂରଚନା xaddr *a)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ବାଛ (a->af) {
	ସ୍ଥିତି AF_INET:
		ଫେରନ୍ତୁ (a->v4.s_addr == 0 ? 0 : -1);
	ସ୍ଥିତି AF_INET6:
		ପାଇଁ (i = 0; i < 4; i++)
			ଯଦି (a->addr32[i] != 0)
				ଫେରନ୍ତୁ -1;
		ଫେରନ୍ତୁ 0;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
ଶୂନ୍ୟ
addr_increment(ସଂରଚନା xaddr *a)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	uint32_t n;

	ବାଛ (a->af) {
	ସ୍ଥିତି AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି AF_INET6:
		ପାଇଁ (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			ଯଦି (n != 0)
				ଭାଙ୍ଗ;
		}
		ଭାଙ୍ଗ;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_host_is_all0s(ଅଚଳ ସଂରଚନା xaddr *a, u_int masklen)
{
	ସଂରଚନା xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, ଆକାର(tmp_addr));
	ଯଦି (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ଫେରନ୍ତୁ -1;
	ଯଦି (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ addr_is_all0s(&tmp_result);
}

#ଯଦି 0
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_host_to_all0s(ସଂରଚନା xaddr *a, u_int masklen)
{
	ସଂରଚନା xaddr tmp_mask;

	ଯଦି (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		ଫେରନ୍ତୁ (-1);
	ଯଦି (addr_and(a, a, &tmp_mask) == -1)
		ଫେରନ୍ତୁ (-1);
	ଫେରନ୍ତୁ (0);
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_host_to_all1s(ସଂରଚନା xaddr *a, u_int masklen)
{
	ସଂରଚନା xaddr tmp_mask;

	ଯଦି (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ଫେରନ୍ତୁ (-1);
	ଯଦି (addr_or(a, a, &tmp_mask) == -1)
		ଫେରନ୍ତୁ (-1);
	ଫେରନ୍ତୁ (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_pton(ଅଚଳ ଅକ୍ଷର *p, ସଂରଚନା xaddr *n)
{
	ସଂରଚନା addrinfo hints, *ai;

	memset(&hints, '\0', ଆକାର(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ଯଦି (p == ଖାଲି || getaddrinfo(p, ଖାଲି, &hints, &ai) != 0)
		ଫେରନ୍ତୁ -1;

	ଯଦି (ai == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	ଯଦି (ai->ai_addr == ଖାଲି) {
		freeaddrinfo(ai);
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (n != ଖାଲି && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		ଫେରନ୍ତୁ -1;
	}

	freeaddrinfo(ai);
	ଫେରନ୍ତୁ 0;
}

#ଯଦି 0
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_sa_pton(ଅଚଳ ଅକ୍ଷର *h, ଅଚଳ ଅକ୍ଷର *s, ସଂରଚନା sockaddr *sa, socklen_t slen)
{
	ସଂରଚନା addrinfo hints, *ai;

	memset(&hints, '\0', ଆକାର(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ଯଦି (h == ଖାଲି || getaddrinfo(h, s, &hints, &ai) != 0)
		ଫେରନ୍ତୁ -1;

	ଯଦି (ai == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	ଯଦି (ai->ai_addr == ଖାଲି) {
		freeaddrinfo(ai);
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (sa != ଖାଲି) {
		ଯଦି (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			ଫେରନ୍ତୁ -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	ଫେରନ୍ତୁ 0;
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_ntop(ଅଚଳ ସଂରଚନା xaddr *n, ଅକ୍ଷର *p, size_t len)
{
	ସଂରଚନା sockaddr_storage ss;
	socklen_t slen = ଆକାର(ss);

	ଯଦି (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		ଫେରନ୍ତୁ -1;
	ଯଦି (p == ଖାଲି || len == 0)
		ଫେରନ୍ତୁ -1;
	ଯଦି (getnameinfo(_SA(&ss), slen, p, len, ଖାଲି, 0,
	    NI_NUMERICHOST) != 0)
		ଫେରନ୍ତୁ -1;

	ଫେରନ୍ତୁ 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_pton_cidr(ଅଚଳ ଅକ୍ଷର *p, ସଂରଚନା xaddr *n, u_int *l)
{
	ସଂରଚନା xaddr tmp;
	u_int masklen = 999;
	ଅକ୍ଷର addrbuf[64], *mp;
	ଅଚଳ ଅକ୍ଷର *errstr;

	/* Don't modify argument */
	ଯଦି (p == ଖାଲି || strlcpy(addrbuf, p, ଆକାର(addrbuf)) >= ଆକାର(addrbuf))
		ଫେରନ୍ତୁ -1;

	ଯଦି ((mp = strchr(addrbuf, '/')) != ଖାଲି) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		ଯଦି (errstr)
			ଫେରନ୍ତୁ -1;
	}

	ଯଦି (addr_pton(addrbuf, &tmp) == -1)
		ଫେରନ୍ତୁ -1;

	ଯଦି (mp == ଖାଲି)
		masklen = addr_unicast_masklen(tmp.af);
	ଯଦି (masklen_valid(tmp.af, masklen) == -1)
		ଫେରନ୍ତୁ -2;
	ଯଦି (addr_host_is_all0s(&tmp, masklen) != 0)
		ଫେରନ୍ତୁ -2;

	ଯଦି (n != ଖାଲି)
		memcpy(n, &tmp, ଆକାର(*n));
	ଯଦି (l != ଖାଲି)
		*l = masklen;

	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
addr_netmatch(ଅଚଳ ସଂରଚନା xaddr *host, ଅଚଳ ସଂରଚନା xaddr *net, u_int masklen)
{
	ସଂରଚନା xaddr tmp_mask, tmp_result;

	ଯଦି (host->af != net->af)
		ଫେରନ୍ତୁ -1;

	ଯଦି (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		ଫେରନ୍ତୁ -1;
	ଯଦି (addr_and(&tmp_result, host, &tmp_mask) == -1)
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ addr_cmp(&tmp_result, net);
}
