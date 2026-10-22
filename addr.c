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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "addr.h"

#define _SA(x)	((கட்டமைப்பு sockaddr *)(x))

நிலையான முழு
addr_unicast_masklen(முழு af)
{
	தேர்வு (af) {
	நிலை AF_INET:
		திரும்பு 32;
	நிலை AF_INET6:
		திரும்பு 128;
	இயல்பு:
		திரும்பு -1;
	}
}

நிலையான உள்வரி முழு
masklen_valid(முழு af, u_int masklen)
{
	தேர்வு (af) {
	நிலை AF_INET:
		திரும்பு masklen <= 32 ? 0 : -1;
	நிலை AF_INET6:
		திரும்பு masklen <= 128 ? 0 : -1;
	இயல்பு:
		திரும்பு -1;
	}
}

நிலையான முழு
addr_xaddr_to_sa(மாறிலி கட்டமைப்பு xaddr *xa, கட்டமைப்பு sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	கட்டமைப்பு sockaddr_in *in4 = (கட்டமைப்பு sockaddr_in *)sa;
	கட்டமைப்பு sockaddr_in6 *in6 = (கட்டமைப்பு sockaddr_in6 *)sa;

	எனில் (xa == வெற்று || sa == வெற்று || len == வெற்று)
		திரும்பு -1;

	தேர்வு (xa->af) {
	நிலை AF_INET:
		எனில் (*len < அளவு(*in4))
			திரும்பு -1;
		memset(sa, '\0', அளவு(*in4));
		*len = அளவு(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = அளவு(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, அளவு(in4->sin_addr));
		நிறுத்து;
	நிலை AF_INET6:
		எனில் (*len < அளவு(*in6))
			திரும்பு -1;
		memset(sa, '\0', அளவு(*in6));
		*len = அளவு(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = அளவு(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, அளவு(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		நிறுத்து;
	இயல்பு:
		திரும்பு -1;
	}
	திரும்பு 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
முழு
addr_sa_to_xaddr(கட்டமைப்பு sockaddr *sa, socklen_t slen, கட்டமைப்பு xaddr *xa)
{
	கட்டமைப்பு sockaddr_in *in4 = (கட்டமைப்பு sockaddr_in *)sa;
	கட்டமைப்பு sockaddr_in6 *in6 = (கட்டமைப்பு sockaddr_in6 *)sa;

	memset(xa, '\0', அளவு(*xa));

	தேர்வு (sa->sa_family) {
	நிலை AF_INET:
		எனில் (slen < (socklen_t)அளவு(*in4))
			திரும்பு -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, அளவு(xa->v4));
		நிறுத்து;
	நிலை AF_INET6:
		எனில் (slen < (socklen_t)அளவு(*in6))
			திரும்பு -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, அளவு(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		நிறுத்து;
	இயல்பு:
		திரும்பு -1;
	}

	திரும்பு 0;
}

நிலையான முழு
addr_invert(கட்டமைப்பு xaddr *n)
{
	முழு i;

	எனில் (n == வெற்று)
		திரும்பு -1;

	தேர்வு (n->af) {
	நிலை AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		திரும்பு 0;
	நிலை AF_INET6:
		க்கு (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		திரும்பு 0;
	இயல்பு:
		திரும்பு -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
முழு
addr_netmask(முழு af, u_int l, கட்டமைப்பு xaddr *n)
{
	முழு i;

	எனில் (masklen_valid(af, l) != 0 || n == வெற்று)
		திரும்பு -1;

	memset(n, '\0', அளவு(*n));
	தேர்வு (af) {
	நிலை AF_INET:
		n->af = AF_INET;
		எனில் (l == 0)
			திரும்பு 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		திரும்பு 0;
	நிலை AF_INET6:
		n->af = AF_INET6;
		க்கு (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		எனில் (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		திரும்பு 0;
	இயல்பு:
		திரும்பு -1;
	}
}

நிலையான முழு
addr_hostmask(முழு af, u_int l, கட்டமைப்பு xaddr *n)
{
	எனில் (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		திரும்பு -1;
	திரும்பு 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
முழு
addr_and(கட்டமைப்பு xaddr *dst, மாறிலி கட்டமைப்பு xaddr *a, மாறிலி கட்டமைப்பு xaddr *b)
{
	முழு i;

	எனில் (dst == வெற்று || a == வெற்று || b == வெற்று || a->af != b->af)
		திரும்பு -1;

	memcpy(dst, a, அளவு(*dst));
	தேர்வு (a->af) {
	நிலை AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		திரும்பு 0;
	நிலை AF_INET6:
		dst->scope_id = a->scope_id;
		க்கு (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		திரும்பு 0;
	இயல்பு:
		திரும்பு -1;
	}
}

நிலையான முழு
addr_or(கட்டமைப்பு xaddr *dst, மாறிலி கட்டமைப்பு xaddr *a, மாறிலி கட்டமைப்பு xaddr *b)
{
	முழு i;

	எனில் (dst == வெற்று || a == வெற்று || b == வெற்று || a->af != b->af)
		திரும்பு (-1);

	memcpy(dst, a, அளவு(*dst));
	தேர்வு (a->af) {
	நிலை AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		திரும்பு (0);
	நிலை AF_INET6:
		க்கு (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		திரும்பு (0);
	இயல்பு:
		திரும்பு (-1);
	}
}

முழு
addr_cmp(மாறிலி கட்டமைப்பு xaddr *a, மாறிலி கட்டமைப்பு xaddr *b)
{
	முழு i;

	எனில் (a->af != b->af)
		திரும்பு (a->af == AF_INET6 ? 1 : -1);

	தேர்வு (a->af) {
	நிலை AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		எனில் (a->v4.s_addr == b->v4.s_addr)
			திரும்பு 0;
		திரும்பு (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	நிலை AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		க்கு (i = 0; i < 16; i++)
			எனில் (a->addr8[i] - b->addr8[i] != 0)
				திரும்பு (a->addr8[i] - b->addr8[i]);
		எனில் (a->scope_id == b->scope_id)
			திரும்பு (0);
		திரும்பு (a->scope_id > b->scope_id ? 1 : -1);
	இயல்பு:
		திரும்பு (-1);
	}
}

நிலையான முழு
addr_is_all0s(மாறிலி கட்டமைப்பு xaddr *a)
{
	முழு i;

	தேர்வு (a->af) {
	நிலை AF_INET:
		திரும்பு (a->v4.s_addr == 0 ? 0 : -1);
	நிலை AF_INET6:
		க்கு (i = 0; i < 4; i++)
			எனில் (a->addr32[i] != 0)
				திரும்பு -1;
		திரும்பு 0;
	இயல்பு:
		திரும்பு -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
வெறுமை
addr_increment(கட்டமைப்பு xaddr *a)
{
	முழு i;
	uint32_t n;

	தேர்வு (a->af) {
	நிலை AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		நிறுத்து;
	நிலை AF_INET6:
		க்கு (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			எனில் (n != 0)
				நிறுத்து;
		}
		நிறுத்து;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
நிலையான முழு
addr_host_is_all0s(மாறிலி கட்டமைப்பு xaddr *a, u_int masklen)
{
	கட்டமைப்பு xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, அளவு(tmp_addr));
	எனில் (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		திரும்பு -1;
	எனில் (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		திரும்பு -1;
	திரும்பு addr_is_all0s(&tmp_result);
}

#எனில் 0
நிலையான முழு
addr_host_to_all0s(கட்டமைப்பு xaddr *a, u_int masklen)
{
	கட்டமைப்பு xaddr tmp_mask;

	எனில் (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		திரும்பு (-1);
	எனில் (addr_and(a, a, &tmp_mask) == -1)
		திரும்பு (-1);
	திரும்பு (0);
}
#endif

முழு
addr_host_to_all1s(கட்டமைப்பு xaddr *a, u_int masklen)
{
	கட்டமைப்பு xaddr tmp_mask;

	எனில் (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		திரும்பு (-1);
	எனில் (addr_or(a, a, &tmp_mask) == -1)
		திரும்பு (-1);
	திரும்பு (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
முழு
addr_pton(மாறிலி எழுத்து *p, கட்டமைப்பு xaddr *n)
{
	கட்டமைப்பு addrinfo hints, *ai;

	memset(&hints, '\0', அளவு(hints));
	hints.ai_flags = AI_NUMERICHOST;

	எனில் (p == வெற்று || getaddrinfo(p, வெற்று, &hints, &ai) != 0)
		திரும்பு -1;

	எனில் (ai == வெற்று)
		திரும்பு -1;

	எனில் (ai->ai_addr == வெற்று) {
		freeaddrinfo(ai);
		திரும்பு -1;
	}

	எனில் (n != வெற்று && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		திரும்பு -1;
	}

	freeaddrinfo(ai);
	திரும்பு 0;
}

#எனில் 0
நிலையான முழு
addr_sa_pton(மாறிலி எழுத்து *h, மாறிலி எழுத்து *s, கட்டமைப்பு sockaddr *sa, socklen_t slen)
{
	கட்டமைப்பு addrinfo hints, *ai;

	memset(&hints, '\0', அளவு(hints));
	hints.ai_flags = AI_NUMERICHOST;

	எனில் (h == வெற்று || getaddrinfo(h, s, &hints, &ai) != 0)
		திரும்பு -1;

	எனில் (ai == வெற்று)
		திரும்பு -1;

	எனில் (ai->ai_addr == வெற்று) {
		freeaddrinfo(ai);
		திரும்பு -1;
	}

	எனில் (sa != வெற்று) {
		எனில் (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			திரும்பு -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	திரும்பு 0;
}
#endif

முழு
addr_ntop(மாறிலி கட்டமைப்பு xaddr *n, எழுத்து *p, size_t len)
{
	கட்டமைப்பு sockaddr_storage ss;
	socklen_t slen = அளவு(ss);

	எனில் (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		திரும்பு -1;
	எனில் (p == வெற்று || len == 0)
		திரும்பு -1;
	எனில் (getnameinfo(_SA(&ss), slen, p, len, வெற்று, 0,
	    NI_NUMERICHOST) != 0)
		திரும்பு -1;

	திரும்பு 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
முழு
addr_pton_cidr(மாறிலி எழுத்து *p, கட்டமைப்பு xaddr *n, u_int *l)
{
	கட்டமைப்பு xaddr tmp;
	u_int masklen = 999;
	எழுத்து addrbuf[64], *mp;
	மாறிலி எழுத்து *errstr;

	/* Don't modify argument */
	எனில் (p == வெற்று || strlcpy(addrbuf, p, அளவு(addrbuf)) >= அளவு(addrbuf))
		திரும்பு -1;

	எனில் ((mp = strchr(addrbuf, '/')) != வெற்று) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		எனில் (errstr)
			திரும்பு -1;
	}

	எனில் (addr_pton(addrbuf, &tmp) == -1)
		திரும்பு -1;

	எனில் (mp == வெற்று)
		masklen = addr_unicast_masklen(tmp.af);
	எனில் (masklen_valid(tmp.af, masklen) == -1)
		திரும்பு -2;
	எனில் (addr_host_is_all0s(&tmp, masklen) != 0)
		திரும்பு -2;

	எனில் (n != வெற்று)
		memcpy(n, &tmp, அளவு(*n));
	எனில் (l != வெற்று)
		*l = masklen;

	திரும்பு 0;
}

முழு
addr_netmatch(மாறிலி கட்டமைப்பு xaddr *host, மாறிலி கட்டமைப்பு xaddr *net, u_int masklen)
{
	கட்டமைப்பு xaddr tmp_mask, tmp_result;

	எனில் (host->af != net->af)
		திரும்பு -1;

	எனில் (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		திரும்பு -1;
	எனில் (addr_and(&tmp_result, host, &tmp_mask) == -1)
		திரும்பு -1;
	திரும்பு addr_cmp(&tmp_result, net);
}
