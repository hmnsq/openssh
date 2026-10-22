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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "addr.h"

#define _SA(x)	((ಸಂರಚನಾ sockaddr *)(x))

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
addr_unicast_masklen(ಪೂರ್ಣಾಙ್ಕ af)
{
	ವಿಕಲ್ಪ (af) {
	ಪಕ್ಷ AF_INET:
		ಪ್ರತ್ಯಾಗಮ 32;
	ಪಕ್ಷ AF_INET6:
		ಪ್ರತ್ಯಾಗಮ 128;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಪೂರ್ಣಾಙ್ಕ
masklen_valid(ಪೂರ್ಣಾಙ್ಕ af, u_int masklen)
{
	ವಿಕಲ್ಪ (af) {
	ಪಕ್ಷ AF_INET:
		ಪ್ರತ್ಯಾಗಮ masklen <= 32 ? 0 : -1;
	ಪಕ್ಷ AF_INET6:
		ಪ್ರತ್ಯಾಗಮ masklen <= 128 ? 0 : -1;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
addr_xaddr_to_sa(ಧ್ರುವ ಸಂರಚನಾ xaddr *xa, ಸಂರಚನಾ sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	ಸಂರಚನಾ sockaddr_in *in4 = (ಸಂರಚನಾ sockaddr_in *)sa;
	ಸಂರಚನಾ sockaddr_in6 *in6 = (ಸಂರಚನಾ sockaddr_in6 *)sa;

	ಯದಿ (xa == ರಿಕ್ತ || sa == ರಿಕ್ತ || len == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	ವಿಕಲ್ಪ (xa->af) {
	ಪಕ್ಷ AF_INET:
		ಯದಿ (*len < ಪರಿಮಾಣ(*in4))
			ಪ್ರತ್ಯಾಗಮ -1;
		memset(sa, '\0', ಪರಿಮಾಣ(*in4));
		*len = ಪರಿಮಾಣ(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = ಪರಿಮಾಣ(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, ಪರಿಮಾಣ(in4->sin_addr));
		ಭಙ್ಗ;
	ಪಕ್ಷ AF_INET6:
		ಯದಿ (*len < ಪರಿಮಾಣ(*in6))
			ಪ್ರತ್ಯಾಗಮ -1;
		memset(sa, '\0', ಪರಿಮಾಣ(*in6));
		*len = ಪರಿಮಾಣ(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = ಪರಿಮಾಣ(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, ಪರಿಮಾಣ(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
addr_sa_to_xaddr(ಸಂರಚನಾ sockaddr *sa, socklen_t slen, ಸಂರಚನಾ xaddr *xa)
{
	ಸಂರಚನಾ sockaddr_in *in4 = (ಸಂರಚನಾ sockaddr_in *)sa;
	ಸಂರಚನಾ sockaddr_in6 *in6 = (ಸಂರಚನಾ sockaddr_in6 *)sa;

	memset(xa, '\0', ಪರಿಮಾಣ(*xa));

	ವಿಕಲ್ಪ (sa->sa_family) {
	ಪಕ್ಷ AF_INET:
		ಯದಿ (slen < (socklen_t)ಪರಿಮಾಣ(*in4))
			ಪ್ರತ್ಯಾಗಮ -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, ಪರಿಮಾಣ(xa->v4));
		ಭಙ್ಗ;
	ಪಕ್ಷ AF_INET6:
		ಯದಿ (slen < (socklen_t)ಪರಿಮಾಣ(*in6))
			ಪ್ರತ್ಯಾಗಮ -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, ಪರಿಮಾಣ(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
addr_invert(ಸಂರಚನಾ xaddr *n)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (n == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	ವಿಕಲ್ಪ (n->af) {
	ಪಕ್ಷ AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ AF_INET6:
		ಪ್ರತಿ (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
addr_netmask(ಪೂರ್ಣಾಙ್ಕ af, u_int l, ಸಂರಚನಾ xaddr *n)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (masklen_valid(af, l) != 0 || n == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	memset(n, '\0', ಪರಿಮಾಣ(*n));
	ವಿಕಲ್ಪ (af) {
	ಪಕ್ಷ AF_INET:
		n->af = AF_INET;
		ಯದಿ (l == 0)
			ಪ್ರತ್ಯಾಗಮ 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ AF_INET6:
		n->af = AF_INET6;
		ಪ್ರತಿ (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		ಯದಿ (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
addr_hostmask(ಪೂರ್ಣಾಙ್ಕ af, u_int l, ಸಂರಚನಾ xaddr *n)
{
	ಯದಿ (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
addr_and(ಸಂರಚನಾ xaddr *dst, ಧ್ರುವ ಸಂರಚನಾ xaddr *a, ಧ್ರುವ ಸಂರಚನಾ xaddr *b)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (dst == ರಿಕ್ತ || a == ರಿಕ್ತ || b == ರಿಕ್ತ || a->af != b->af)
		ಪ್ರತ್ಯಾಗಮ -1;

	memcpy(dst, a, ಪರಿಮಾಣ(*dst));
	ವಿಕಲ್ಪ (a->af) {
	ಪಕ್ಷ AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ AF_INET6:
		dst->scope_id = a->scope_id;
		ಪ್ರತಿ (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
addr_or(ಸಂರಚನಾ xaddr *dst, ಧ್ರುವ ಸಂರಚನಾ xaddr *a, ಧ್ರುವ ಸಂರಚನಾ xaddr *b)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (dst == ರಿಕ್ತ || a == ರಿಕ್ತ || b == ರಿಕ್ತ || a->af != b->af)
		ಪ್ರತ್ಯಾಗಮ (-1);

	memcpy(dst, a, ಪರಿಮಾಣ(*dst));
	ವಿಕಲ್ಪ (a->af) {
	ಪಕ್ಷ AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		ಪ್ರತ್ಯಾಗಮ (0);
	ಪಕ್ಷ AF_INET6:
		ಪ್ರತಿ (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		ಪ್ರತ್ಯಾಗಮ (0);
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
}

ಪೂರ್ಣಾಙ್ಕ
addr_cmp(ಧ್ರುವ ಸಂರಚನಾ xaddr *a, ಧ್ರುವ ಸಂರಚನಾ xaddr *b)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (a->af != b->af)
		ಪ್ರತ್ಯಾಗಮ (a->af == AF_INET6 ? 1 : -1);

	ವಿಕಲ್ಪ (a->af) {
	ಪಕ್ಷ AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		ಯದಿ (a->v4.s_addr == b->v4.s_addr)
			ಪ್ರತ್ಯಾಗಮ 0;
		ಪ್ರತ್ಯಾಗಮ (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	ಪಕ್ಷ AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		ಪ್ರತಿ (i = 0; i < 16; i++)
			ಯದಿ (a->addr8[i] - b->addr8[i] != 0)
				ಪ್ರತ್ಯಾಗಮ (a->addr8[i] - b->addr8[i]);
		ಯದಿ (a->scope_id == b->scope_id)
			ಪ್ರತ್ಯಾಗಮ (0);
		ಪ್ರತ್ಯಾಗಮ (a->scope_id > b->scope_id ? 1 : -1);
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
addr_is_all0s(ಧ್ರುವ ಸಂರಚನಾ xaddr *a)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ವಿಕಲ್ಪ (a->af) {
	ಪಕ್ಷ AF_INET:
		ಪ್ರತ್ಯಾಗಮ (a->v4.s_addr == 0 ? 0 : -1);
	ಪಕ್ಷ AF_INET6:
		ಪ್ರತಿ (i = 0; i < 4; i++)
			ಯದಿ (a->addr32[i] != 0)
				ಪ್ರತ್ಯಾಗಮ -1;
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
ಶೂನ್ಯ
addr_increment(ಸಂರಚನಾ xaddr *a)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	uint32_t n;

	ವಿಕಲ್ಪ (a->af) {
	ಪಕ್ಷ AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		ಭಙ್ಗ;
	ಪಕ್ಷ AF_INET6:
		ಪ್ರತಿ (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			ಯದಿ (n != 0)
				ಭಙ್ಗ;
		}
		ಭಙ್ಗ;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
addr_host_is_all0s(ಧ್ರುವ ಸಂರಚನಾ xaddr *a, u_int masklen)
{
	ಸಂರಚನಾ xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, ಪರಿಮಾಣ(tmp_addr));
	ಯದಿ (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ addr_is_all0s(&tmp_result);
}

#ಯದಿ 0
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
addr_host_to_all0s(ಸಂರಚನಾ xaddr *a, u_int masklen)
{
	ಸಂರಚನಾ xaddr tmp_mask;

	ಯದಿ (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಯದಿ (addr_and(a, a, &tmp_mask) == -1)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಪ್ರತ್ಯಾಗಮ (0);
}
#endif

ಪೂರ್ಣಾಙ್ಕ
addr_host_to_all1s(ಸಂರಚನಾ xaddr *a, u_int masklen)
{
	ಸಂರಚನಾ xaddr tmp_mask;

	ಯದಿ (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಯದಿ (addr_or(a, a, &tmp_mask) == -1)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಪ್ರತ್ಯಾಗಮ (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
ಪೂರ್ಣಾಙ್ಕ
addr_pton(ಧ್ರುವ ವರ್ಣ *p, ಸಂರಚನಾ xaddr *n)
{
	ಸಂರಚನಾ addrinfo hints, *ai;

	memset(&hints, '\0', ಪರಿಮಾಣ(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ಯದಿ (p == ರಿಕ್ತ || getaddrinfo(p, ರಿಕ್ತ, &hints, &ai) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಯದಿ (ai == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಯದಿ (ai->ai_addr == ರಿಕ್ತ) {
		freeaddrinfo(ai);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (n != ರಿಕ್ತ && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	freeaddrinfo(ai);
	ಪ್ರತ್ಯಾಗಮ 0;
}

#ಯದಿ 0
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
addr_sa_pton(ಧ್ರುವ ವರ್ಣ *h, ಧ್ರುವ ವರ್ಣ *s, ಸಂರಚನಾ sockaddr *sa, socklen_t slen)
{
	ಸಂರಚನಾ addrinfo hints, *ai;

	memset(&hints, '\0', ಪರಿಮಾಣ(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ಯದಿ (h == ರಿಕ್ತ || getaddrinfo(h, s, &hints, &ai) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಯದಿ (ai == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಯದಿ (ai->ai_addr == ರಿಕ್ತ) {
		freeaddrinfo(ai);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (sa != ರಿಕ್ತ) {
		ಯದಿ (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif

ಪೂರ್ಣಾಙ್ಕ
addr_ntop(ಧ್ರುವ ಸಂರಚನಾ xaddr *n, ವರ್ಣ *p, size_t len)
{
	ಸಂರಚನಾ sockaddr_storage ss;
	socklen_t slen = ಪರಿಮಾಣ(ss);

	ಯದಿ (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (p == ರಿಕ್ತ || len == 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (getnameinfo(_SA(&ss), slen, p, len, ರಿಕ್ತ, 0,
	    NI_NUMERICHOST) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
ಪೂರ್ಣಾಙ್ಕ
addr_pton_cidr(ಧ್ರುವ ವರ್ಣ *p, ಸಂರಚನಾ xaddr *n, u_int *l)
{
	ಸಂರಚನಾ xaddr tmp;
	u_int masklen = 999;
	ವರ್ಣ addrbuf[64], *mp;
	ಧ್ರುವ ವರ್ಣ *errstr;

	/* Don't modify argument */
	ಯದಿ (p == ರಿಕ್ತ || strlcpy(addrbuf, p, ಪರಿಮಾಣ(addrbuf)) >= ಪರಿಮಾಣ(addrbuf))
		ಪ್ರತ್ಯಾಗಮ -1;

	ಯದಿ ((mp = strchr(addrbuf, '/')) != ರಿಕ್ತ) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		ಯದಿ (errstr)
			ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (addr_pton(addrbuf, &tmp) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಯದಿ (mp == ರಿಕ್ತ)
		masklen = addr_unicast_masklen(tmp.af);
	ಯದಿ (masklen_valid(tmp.af, masklen) == -1)
		ಪ್ರತ್ಯಾಗಮ -2;
	ಯದಿ (addr_host_is_all0s(&tmp, masklen) != 0)
		ಪ್ರತ್ಯಾಗಮ -2;

	ಯದಿ (n != ರಿಕ್ತ)
		memcpy(n, &tmp, ಪರಿಮಾಣ(*n));
	ಯದಿ (l != ರಿಕ್ತ)
		*l = masklen;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
addr_netmatch(ಧ್ರುವ ಸಂರಚನಾ xaddr *host, ಧ್ರುವ ಸಂರಚನಾ xaddr *net, u_int masklen)
{
	ಸಂರಚನಾ xaddr tmp_mask, tmp_result;

	ಯದಿ (host->af != net->af)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಯದಿ (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (addr_and(&tmp_result, host, &tmp_mask) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ addr_cmp(&tmp_result, net);
}
