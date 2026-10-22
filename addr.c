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

#ವ್ಯಾಖ್ಯಾನಿಸು _SA(x)	((ರಚನೆ sockaddr *)(x))

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
addr_unicast_masklen(ಪೂರ್ಣಾಂಕ af)
{
	ಆಯ್ಕೆ (af) {
	ಸ್ಥಿತಿ AF_INET:
		ಹಿಂತಿರುಗಿ 32;
	ಸ್ಥಿತಿ AF_INET6:
		ಹಿಂತಿರುಗಿ 128;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಪೂರ್ಣಾಂಕ
masklen_valid(ಪೂರ್ಣಾಂಕ af, u_int masklen)
{
	ಆಯ್ಕೆ (af) {
	ಸ್ಥಿತಿ AF_INET:
		ಹಿಂತಿರುಗಿ masklen <= 32 ? 0 : -1;
	ಸ್ಥಿತಿ AF_INET6:
		ಹಿಂತಿರುಗಿ masklen <= 128 ? 0 : -1;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
addr_xaddr_ಗಮ್ಯ_sa(ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *xa, ರಚನೆ sockaddr *sa, socklen_t *len,
    uint16_t ಪೋರ್ಟ್)
{
	ರಚನೆ sockaddr_in *in4 = (ರಚನೆ sockaddr_in *)sa;
	ರಚನೆ sockaddr_in6 *in6 = (ರಚನೆ sockaddr_in6 *)sa;

	ಆದರೆ (xa == ಖಾಲಿ || sa == ಖಾಲಿ || len == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	ಆಯ್ಕೆ (xa->af) {
	ಸ್ಥಿತಿ AF_INET:
		ಆದರೆ (*len < ಗಾತ್ರ(*in4))
			ಹಿಂತಿರುಗಿ -1;
		memset(sa, '\0', ಗಾತ್ರ(*in4));
		*len = ಗಾತ್ರ(*in4);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SOCK_HAS_LEN
		in4->sin_len = ಗಾತ್ರ(*in4);
#ಆದರೆ_ಅಂತ್ಯ
		in4->sin_family = AF_INET;
		in4->sin_port = htons(ಪೋರ್ಟ್);
		ಸ್ಮರಣೆ_ನಕಲು(&in4->sin_addr, &xa->v4, ಗಾತ್ರ(in4->sin_addr));
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ AF_INET6:
		ಆದರೆ (*len < ಗಾತ್ರ(*in6))
			ಹಿಂತಿರುಗಿ -1;
		memset(sa, '\0', ಗಾತ್ರ(*in6));
		*len = ಗಾತ್ರ(*in6);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SOCK_HAS_LEN
		in6->sin6_len = ಗಾತ್ರ(*in6);
#ಆದರೆ_ಅಂತ್ಯ
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(ಪೋರ್ಟ್);
		ಸ್ಮರಣೆ_ನಕಲು(&in6->sin6_addr, &xa->v6, ಗಾತ್ರ(in6->sin6_addr));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#ಆದರೆ_ಅಂತ್ಯ
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
ಪೂರ್ಣಾಂಕ
addr_sa_ಗಮ್ಯ_xaddr(ರಚನೆ sockaddr *sa, socklen_t slen, ರಚನೆ xaddr *xa)
{
	ರಚನೆ sockaddr_in *in4 = (ರಚನೆ sockaddr_in *)sa;
	ರಚನೆ sockaddr_in6 *in6 = (ರಚನೆ sockaddr_in6 *)sa;

	memset(xa, '\0', ಗಾತ್ರ(*xa));

	ಆಯ್ಕೆ (sa->sa_family) {
	ಸ್ಥಿತಿ AF_INET:
		ಆದರೆ (slen < (socklen_t)ಗಾತ್ರ(*in4))
			ಹಿಂತಿರುಗಿ -1;
		xa->af = AF_INET;
		ಸ್ಮರಣೆ_ನಕಲು(&xa->v4, &in4->sin_addr, ಗಾತ್ರ(xa->v4));
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ AF_INET6:
		ಆದರೆ (slen < (socklen_t)ಗಾತ್ರ(*in6))
			ಹಿಂತಿರುಗಿ -1;
		xa->af = AF_INET6;
		ಸ್ಮರಣೆ_ನಕಲು(&xa->v6, &in6->sin6_addr, ಗಾತ್ರ(xa->v6));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#ಆದರೆ_ಅಂತ್ಯ
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
addr_invert(ರಚನೆ xaddr *n)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (n == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	ಆಯ್ಕೆ (n->af) {
	ಸ್ಥಿತಿ AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ AF_INET6:
		ಗಾಗಿ (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		ಹಿಂತಿರುಗಿ 0;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
ಪೂರ್ಣಾಂಕ
addr_netmask(ಪೂರ್ಣಾಂಕ af, u_int l, ರಚನೆ xaddr *n)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (masklen_valid(af, l) != 0 || n == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	memset(n, '\0', ಗಾತ್ರ(*n));
	ಆಯ್ಕೆ (af) {
	ಸ್ಥಿತಿ AF_INET:
		n->af = AF_INET;
		ಆದರೆ (l == 0)
			ಹಿಂತಿರುಗಿ 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ AF_INET6:
		n->af = AF_INET6;
		ಗಾಗಿ (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		ಆದರೆ (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		ಹಿಂತಿರುಗಿ 0;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
addr_hostmask(ಪೂರ್ಣಾಂಕ af, u_int l, ರಚನೆ xaddr *n)
{
	ಆದರೆ (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
ಪೂರ್ಣಾಂಕ
addr_and(ರಚನೆ xaddr *dst, ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *a, ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *b)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (dst == ಖಾಲಿ || a == ಖಾಲಿ || b == ಖಾಲಿ || a->af != b->af)
		ಹಿಂತಿರುಗಿ -1;

	ಸ್ಮರಣೆ_ನಕಲು(dst, a, ಗಾತ್ರ(*dst));
	ಆಯ್ಕೆ (a->af) {
	ಸ್ಥಿತಿ AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ AF_INET6:
		dst->scope_id = a->scope_id;
		ಗಾಗಿ (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		ಹಿಂತಿರುಗಿ 0;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
addr_or(ರಚನೆ xaddr *dst, ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *a, ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *b)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (dst == ಖಾಲಿ || a == ಖಾಲಿ || b == ಖಾಲಿ || a->af != b->af)
		ಹಿಂತಿರುಗಿ (-1);

	ಸ್ಮರಣೆ_ನಕಲು(dst, a, ಗಾತ್ರ(*dst));
	ಆಯ್ಕೆ (a->af) {
	ಸ್ಥಿತಿ AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		ಹಿಂತಿರುಗಿ (0);
	ಸ್ಥಿತಿ AF_INET6:
		ಗಾಗಿ (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		ಹಿಂತಿರುಗಿ (0);
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ (-1);
	}
}

ಪೂರ್ಣಾಂಕ
addr_cmp(ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *a, ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *b)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (a->af != b->af)
		ಹಿಂತಿರುಗಿ (a->af == AF_INET6 ? 1 : -1);

	ಆಯ್ಕೆ (a->af) {
	ಸ್ಥಿತಿ AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		ಆದರೆ (a->v4.s_addr == b->v4.s_addr)
			ಹಿಂತಿರುಗಿ 0;
		ಹಿಂತಿರುಗಿ (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	ಸ್ಥಿತಿ AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		ಗಾಗಿ (i = 0; i < 16; i++)
			ಆದರೆ (a->addr8[i] - b->addr8[i] != 0)
				ಹಿಂತಿರುಗಿ (a->addr8[i] - b->addr8[i]);
		ಆದರೆ (a->scope_id == b->scope_id)
			ಹಿಂತಿರುಗಿ (0);
		ಹಿಂತಿರುಗಿ (a->scope_id > b->scope_id ? 1 : -1);
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ (-1);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
addr_is_all0s(ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *a)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆಯ್ಕೆ (a->af) {
	ಸ್ಥಿತಿ AF_INET:
		ಹಿಂತಿರುಗಿ (a->v4.s_addr == 0 ? 0 : -1);
	ಸ್ಥಿತಿ AF_INET6:
		ಗಾಗಿ (i = 0; i < 4; i++)
			ಆದರೆ (a->addr32[i] != 0)
				ಹಿಂತಿರುಗಿ -1;
		ಹಿಂತಿರುಗಿ 0;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
ಶೂನ್ಯ
addr_increment(ರಚನೆ xaddr *a)
{
	ಪೂರ್ಣಾಂಕ i;
	uint32_t n;

	ಆಯ್ಕೆ (a->af) {
	ಸ್ಥಿತಿ AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ AF_INET6:
		ಗಾಗಿ (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			ಆದರೆ (n != 0)
				ನಿಲ್ಲಿಸು;
		}
		ನಿಲ್ಲಿಸು;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
addr_host_is_all0s(ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *a, u_int masklen)
{
	ರಚನೆ xaddr tmp_addr, tmp_ಮುಖವಾಡ, tmp_ಫಲಿತಾಂಶ;

	ಸ್ಮರಣೆ_ನಕಲು(&tmp_addr, a, ಗಾತ್ರ(tmp_addr));
	ಆದರೆ (addr_hostmask(a->af, masklen, &tmp_ಮುಖವಾಡ) == -1)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (addr_and(&tmp_ಫಲಿತಾಂಶ, &tmp_addr, &tmp_ಮುಖವಾಡ) == -1)
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ addr_is_all0s(&tmp_ಫಲಿತಾಂಶ);
}

#ಆದರೆ 0
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
addr_host_ಗಮ್ಯ_all0s(ರಚನೆ xaddr *a, u_int masklen)
{
	ರಚನೆ xaddr tmp_ಮುಖವಾಡ;

	ಆದರೆ (addr_netmask(a->af, masklen, &tmp_ಮುಖವಾಡ) == -1)
		ಹಿಂತಿರುಗಿ (-1);
	ಆದರೆ (addr_and(a, a, &tmp_ಮುಖವಾಡ) == -1)
		ಹಿಂತಿರುಗಿ (-1);
	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
addr_host_ಗಮ್ಯ_all1s(ರಚನೆ xaddr *a, u_int masklen)
{
	ರಚನೆ xaddr tmp_ಮುಖವಾಡ;

	ಆದರೆ (addr_hostmask(a->af, masklen, &tmp_ಮುಖವಾಡ) == -1)
		ಹಿಂತಿರುಗಿ (-1);
	ಆದರೆ (addr_or(a, a, &tmp_ಮುಖವಾಡ) == -1)
		ಹಿಂತಿರುಗಿ (-1);
	ಹಿಂತಿರುಗಿ (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
ಪೂರ್ಣಾಂಕ
addr_pton(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p, ರಚನೆ xaddr *n)
{
	ರಚನೆ addrinfo hints, *ai;

	memset(&hints, '\0', ಗಾತ್ರ(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ಆದರೆ (p == ಖಾಲಿ || getaddrinfo(p, ಖಾಲಿ, &hints, &ai) != 0)
		ಹಿಂತಿರುಗಿ -1;

	ಆದರೆ (ai == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	ಆದರೆ (ai->ai_addr == ಖಾಲಿ) {
		freeaddrinfo(ai);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (n != ಖಾಲಿ && addr_sa_ಗಮ್ಯ_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		ಹಿಂತಿರುಗಿ -1;
	}

	freeaddrinfo(ai);
	ಹಿಂತಿರುಗಿ 0;
}

#ಆದರೆ 0
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
addr_sa_pton(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *h, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ರಚನೆ sockaddr *sa, socklen_t slen)
{
	ರಚನೆ addrinfo hints, *ai;

	memset(&hints, '\0', ಗಾತ್ರ(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ಆದರೆ (h == ಖಾಲಿ || getaddrinfo(h, s, &hints, &ai) != 0)
		ಹಿಂತಿರುಗಿ -1;

	ಆದರೆ (ai == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	ಆದರೆ (ai->ai_addr == ಖಾಲಿ) {
		freeaddrinfo(ai);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (sa != ಖಾಲಿ) {
		ಆದರೆ (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			ಹಿಂತಿರುಗಿ -1;
		}
		ಸ್ಮರಣೆ_ನಕಲು(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
addr_ntop(ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *n, ಅಕ್ಷರ *p, ಗಾತ್ರ_t len)
{
	ರಚನೆ sockaddr_storage ss;
	socklen_t slen = ಗಾತ್ರ(ss);

	ಆದರೆ (addr_xaddr_ಗಮ್ಯ_sa(n, _SA(&ss), &slen, 0) == -1)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (p == ಖಾಲಿ || len == 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (getnameinfo(_SA(&ss), slen, p, len, ಖಾಲಿ, 0,
	    NI_NUMERICHOST) != 0)
		ಹಿಂತಿರುಗಿ -1;

	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
ಪೂರ್ಣಾಂಕ
addr_pton_cidr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p, ರಚನೆ xaddr *n, u_int *l)
{
	ರಚನೆ xaddr tmp;
	u_int masklen = 999;
	ಅಕ್ಷರ addrbuf[64], *mp;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;

	/* Don't modify argument */
	ಆದರೆ (p == ಖಾಲಿ || strlcpy(addrbuf, p, ಗಾತ್ರ(addrbuf)) >= ಗಾತ್ರ(addrbuf))
		ಹಿಂತಿರುಗಿ -1;

	ಆದರೆ ((mp = strchr(addrbuf, '/')) != ಖಾಲಿ) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &errstr);
		ಆದರೆ (errstr)
			ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (addr_pton(addrbuf, &tmp) == -1)
		ಹಿಂತಿರುಗಿ -1;

	ಆದರೆ (mp == ಖಾಲಿ)
		masklen = addr_unicast_masklen(tmp.af);
	ಆದರೆ (masklen_valid(tmp.af, masklen) == -1)
		ಹಿಂತಿರುಗಿ -2;
	ಆದರೆ (addr_host_is_all0s(&tmp, masklen) != 0)
		ಹಿಂತಿರುಗಿ -2;

	ಆದರೆ (n != ಖಾಲಿ)
		ಸ್ಮರಣೆ_ನಕಲು(n, &tmp, ಗಾತ್ರ(*n));
	ಆದರೆ (l != ಖಾಲಿ)
		*l = masklen;

	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
addr_netmatch(ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *host, ಸ್ಥಿರಾಂಕ ರಚನೆ xaddr *net, u_int masklen)
{
	ರಚನೆ xaddr tmp_ಮುಖವಾಡ, tmp_ಫಲಿತಾಂಶ;

	ಆದರೆ (host->af != net->af)
		ಹಿಂತಿರುಗಿ -1;

	ಆದರೆ (addr_netmask(host->af, masklen, &tmp_ಮುಖವಾಡ) == -1)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (addr_and(&tmp_ಫಲಿತಾಂಶ, host, &tmp_ಮುಖವಾಡ) == -1)
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ addr_cmp(&tmp_ಫಲಿತಾಂಶ, net);
}
