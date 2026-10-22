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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব "addr.h"

#define _SA(x)	((কাঠামো sockaddr *)(x))

স্থির পূর্ণসংখ্যা
addr_unicast_masklen(পূর্ণসংখ্যা af)
{
	নির্বাচন (af) {
	ক্ষেত্র AF_INET:
		ফেরত 32;
	ক্ষেত্র AF_INET6:
		ফেরত 128;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

স্থির অন্তঃরেখ পূর্ণসংখ্যা
masklen_valid(পূর্ণসংখ্যা af, u_int masklen)
{
	নির্বাচন (af) {
	ক্ষেত্র AF_INET:
		ফেরত masklen <= 32 ? 0 : -1;
	ক্ষেত্র AF_INET6:
		ফেরত masklen <= 128 ? 0 : -1;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

স্থির পূর্ণসংখ্যা
addr_xaddr_to_sa(ধ্রুবক কাঠামো xaddr *xa, কাঠামো sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	কাঠামো sockaddr_in *in4 = (কাঠামো sockaddr_in *)sa;
	কাঠামো sockaddr_in6 *in6 = (কাঠামো sockaddr_in6 *)sa;

	যদি (xa == ফাঁকা || sa == ফাঁকা || len == ফাঁকা)
		ফেরত -1;

	নির্বাচন (xa->af) {
	ক্ষেত্র AF_INET:
		যদি (*len < আকার(*in4))
			ফেরত -1;
		memset(sa, '\0', আকার(*in4));
		*len = আকার(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = আকার(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, আকার(in4->sin_addr));
		বিরতি;
	ক্ষেত্র AF_INET6:
		যদি (*len < আকার(*in6))
			ফেরত -1;
		memset(sa, '\0', আকার(*in6));
		*len = আকার(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = আকার(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, আকার(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		বিরতি;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
	ফেরত 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
পূর্ণসংখ্যা
addr_sa_to_xaddr(কাঠামো sockaddr *sa, socklen_t slen, কাঠামো xaddr *xa)
{
	কাঠামো sockaddr_in *in4 = (কাঠামো sockaddr_in *)sa;
	কাঠামো sockaddr_in6 *in6 = (কাঠামো sockaddr_in6 *)sa;

	memset(xa, '\0', আকার(*xa));

	নির্বাচন (sa->sa_family) {
	ক্ষেত্র AF_INET:
		যদি (slen < (socklen_t)আকার(*in4))
			ফেরত -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, আকার(xa->v4));
		বিরতি;
	ক্ষেত্র AF_INET6:
		যদি (slen < (socklen_t)আকার(*in6))
			ফেরত -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, আকার(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		বিরতি;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
addr_invert(কাঠামো xaddr *n)
{
	পূর্ণসংখ্যা i;

	যদি (n == ফাঁকা)
		ফেরত -1;

	নির্বাচন (n->af) {
	ক্ষেত্র AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		ফেরত 0;
	ক্ষেত্র AF_INET6:
		জন্য (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		ফেরত 0;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
পূর্ণসংখ্যা
addr_netmask(পূর্ণসংখ্যা af, u_int l, কাঠামো xaddr *n)
{
	পূর্ণসংখ্যা i;

	যদি (masklen_valid(af, l) != 0 || n == ফাঁকা)
		ফেরত -1;

	memset(n, '\0', আকার(*n));
	নির্বাচন (af) {
	ক্ষেত্র AF_INET:
		n->af = AF_INET;
		যদি (l == 0)
			ফেরত 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		ফেরত 0;
	ক্ষেত্র AF_INET6:
		n->af = AF_INET6;
		জন্য (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		যদি (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		ফেরত 0;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

স্থির পূর্ণসংখ্যা
addr_hostmask(পূর্ণসংখ্যা af, u_int l, কাঠামো xaddr *n)
{
	যদি (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		ফেরত -1;
	ফেরত 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
পূর্ণসংখ্যা
addr_and(কাঠামো xaddr *dst, ধ্রুবক কাঠামো xaddr *a, ধ্রুবক কাঠামো xaddr *b)
{
	পূর্ণসংখ্যা i;

	যদি (dst == ফাঁকা || a == ফাঁকা || b == ফাঁকা || a->af != b->af)
		ফেরত -1;

	memcpy(dst, a, আকার(*dst));
	নির্বাচন (a->af) {
	ক্ষেত্র AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		ফেরত 0;
	ক্ষেত্র AF_INET6:
		dst->scope_id = a->scope_id;
		জন্য (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		ফেরত 0;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

স্থির পূর্ণসংখ্যা
addr_or(কাঠামো xaddr *dst, ধ্রুবক কাঠামো xaddr *a, ধ্রুবক কাঠামো xaddr *b)
{
	পূর্ণসংখ্যা i;

	যদি (dst == ফাঁকা || a == ফাঁকা || b == ফাঁকা || a->af != b->af)
		ফেরত (-1);

	memcpy(dst, a, আকার(*dst));
	নির্বাচন (a->af) {
	ক্ষেত্র AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		ফেরত (0);
	ক্ষেত্র AF_INET6:
		জন্য (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		ফেরত (0);
	পূর্বনির্ধারিত:
		ফেরত (-1);
	}
}

পূর্ণসংখ্যা
addr_cmp(ধ্রুবক কাঠামো xaddr *a, ধ্রুবক কাঠামো xaddr *b)
{
	পূর্ণসংখ্যা i;

	যদি (a->af != b->af)
		ফেরত (a->af == AF_INET6 ? 1 : -1);

	নির্বাচন (a->af) {
	ক্ষেত্র AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		যদি (a->v4.s_addr == b->v4.s_addr)
			ফেরত 0;
		ফেরত (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	ক্ষেত্র AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		জন্য (i = 0; i < 16; i++)
			যদি (a->addr8[i] - b->addr8[i] != 0)
				ফেরত (a->addr8[i] - b->addr8[i]);
		যদি (a->scope_id == b->scope_id)
			ফেরত (0);
		ফেরত (a->scope_id > b->scope_id ? 1 : -1);
	পূর্বনির্ধারিত:
		ফেরত (-1);
	}
}

স্থির পূর্ণসংখ্যা
addr_is_all0s(ধ্রুবক কাঠামো xaddr *a)
{
	পূর্ণসংখ্যা i;

	নির্বাচন (a->af) {
	ক্ষেত্র AF_INET:
		ফেরত (a->v4.s_addr == 0 ? 0 : -1);
	ক্ষেত্র AF_INET6:
		জন্য (i = 0; i < 4; i++)
			যদি (a->addr32[i] != 0)
				ফেরত -1;
		ফেরত 0;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
শূন্য
addr_increment(কাঠামো xaddr *a)
{
	পূর্ণসংখ্যা i;
	uint32_t n;

	নির্বাচন (a->af) {
	ক্ষেত্র AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		বিরতি;
	ক্ষেত্র AF_INET6:
		জন্য (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			যদি (n != 0)
				বিরতি;
		}
		বিরতি;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
স্থির পূর্ণসংখ্যা
addr_host_is_all0s(ধ্রুবক কাঠামো xaddr *a, u_int masklen)
{
	কাঠামো xaddr tmp_addr, tmp_mask, tmp_ফলাফল;

	memcpy(&tmp_addr, a, আকার(tmp_addr));
	যদি (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ফেরত -1;
	যদি (addr_and(&tmp_ফলাফল, &tmp_addr, &tmp_mask) == -1)
		ফেরত -1;
	ফেরত addr_is_all0s(&tmp_ফলাফল);
}

#যদি 0
স্থির পূর্ণসংখ্যা
addr_host_to_all0s(কাঠামো xaddr *a, u_int masklen)
{
	কাঠামো xaddr tmp_mask;

	যদি (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		ফেরত (-1);
	যদি (addr_and(a, a, &tmp_mask) == -1)
		ফেরত (-1);
	ফেরত (0);
}
#endif

পূর্ণসংখ্যা
addr_host_to_all1s(কাঠামো xaddr *a, u_int masklen)
{
	কাঠামো xaddr tmp_mask;

	যদি (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ফেরত (-1);
	যদি (addr_or(a, a, &tmp_mask) == -1)
		ফেরত (-1);
	ফেরত (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
পূর্ণসংখ্যা
addr_pton(ধ্রুবক অক্ষর *p, কাঠামো xaddr *n)
{
	কাঠামো addrinfo hints, *ai;

	memset(&hints, '\0', আকার(hints));
	hints.ai_flags = AI_NUMERICHOST;

	যদি (p == ফাঁকা || getaddrinfo(p, ফাঁকা, &hints, &ai) != 0)
		ফেরত -1;

	যদি (ai == ফাঁকা)
		ফেরত -1;

	যদি (ai->ai_addr == ফাঁকা) {
		freeaddrinfo(ai);
		ফেরত -1;
	}

	যদি (n != ফাঁকা && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		ফেরত -1;
	}

	freeaddrinfo(ai);
	ফেরত 0;
}

#যদি 0
স্থির পূর্ণসংখ্যা
addr_sa_pton(ধ্রুবক অক্ষর *h, ধ্রুবক অক্ষর *s, কাঠামো sockaddr *sa, socklen_t slen)
{
	কাঠামো addrinfo hints, *ai;

	memset(&hints, '\0', আকার(hints));
	hints.ai_flags = AI_NUMERICHOST;

	যদি (h == ফাঁকা || getaddrinfo(h, s, &hints, &ai) != 0)
		ফেরত -1;

	যদি (ai == ফাঁকা)
		ফেরত -1;

	যদি (ai->ai_addr == ফাঁকা) {
		freeaddrinfo(ai);
		ফেরত -1;
	}

	যদি (sa != ফাঁকা) {
		যদি (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			ফেরত -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	ফেরত 0;
}
#endif

পূর্ণসংখ্যা
addr_ntop(ধ্রুবক কাঠামো xaddr *n, অক্ষর *p, আকার_t len)
{
	কাঠামো sockaddr_storage ss;
	socklen_t slen = আকার(ss);

	যদি (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		ফেরত -1;
	যদি (p == ফাঁকা || len == 0)
		ফেরত -1;
	যদি (getnameinfo(_SA(&ss), slen, p, len, ফাঁকা, 0,
	    NI_NUMERICHOST) != 0)
		ফেরত -1;

	ফেরত 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
পূর্ণসংখ্যা
addr_pton_cidr(ধ্রুবক অক্ষর *p, কাঠামো xaddr *n, u_int *l)
{
	কাঠামো xaddr tmp;
	u_int masklen = 999;
	অক্ষর addrbuf[64], *mp;
	ধ্রুবক অক্ষর *errstr;

	/* Don't modify argument */
	যদি (p == ফাঁকা || strlcpy(addrbuf, p, আকার(addrbuf)) >= আকার(addrbuf))
		ফেরত -1;

	যদি ((mp = strchr(addrbuf, '/')) != ফাঁকা) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		যদি (errstr)
			ফেরত -1;
	}

	যদি (addr_pton(addrbuf, &tmp) == -1)
		ফেরত -1;

	যদি (mp == ফাঁকা)
		masklen = addr_unicast_masklen(tmp.af);
	যদি (masklen_valid(tmp.af, masklen) == -1)
		ফেরত -2;
	যদি (addr_host_is_all0s(&tmp, masklen) != 0)
		ফেরত -2;

	যদি (n != ফাঁকা)
		memcpy(n, &tmp, আকার(*n));
	যদি (l != ফাঁকা)
		*l = masklen;

	ফেরত 0;
}

পূর্ণসংখ্যা
addr_netmatch(ধ্রুবক কাঠামো xaddr *host, ধ্রুবক কাঠামো xaddr *net, u_int masklen)
{
	কাঠামো xaddr tmp_mask, tmp_ফলাফল;

	যদি (host->af != net->af)
		ফেরত -1;

	যদি (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		ফেরত -1;
	যদি (addr_and(&tmp_ফলাফল, host, &tmp_mask) == -1)
		ফেরত -1;
	ফেরত addr_cmp(&tmp_ফলাফল, net);
}
