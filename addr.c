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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "addr.h"

#define _SA(x)	((ഘടന sockaddr *)(x))

സ്ഥിതം പൂർണ്ണസംഖ്യ
addr_unicast_masklen(പൂർണ്ണസംഖ്യ af)
{
	തിരഞ്ഞെടുപ്പ് (af) {
	അവസ്ഥ AF_INET:
		തിരികെ 32;
	അവസ്ഥ AF_INET6:
		തിരികെ 128;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

സ്ഥിതം വരിയിൽ പൂർണ്ണസംഖ്യ
masklen_valid(പൂർണ്ണസംഖ്യ af, u_int masklen)
{
	തിരഞ്ഞെടുപ്പ് (af) {
	അവസ്ഥ AF_INET:
		തിരികെ masklen <= 32 ? 0 : -1;
	അവസ്ഥ AF_INET6:
		തിരികെ masklen <= 128 ? 0 : -1;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
addr_xaddr_to_sa(സ്ഥിരം ഘടന xaddr *xa, ഘടന sockaddr *sa, socklen_t *len,
    uint16_t port)
{
	ഘടന sockaddr_in *in4 = (ഘടന sockaddr_in *)sa;
	ഘടന sockaddr_in6 *in6 = (ഘടന sockaddr_in6 *)sa;

	എങ്കിൽ (xa == ശൂന്യ || sa == ശൂന്യ || len == ശൂന്യ)
		തിരികെ -1;

	തിരഞ്ഞെടുപ്പ് (xa->af) {
	അവസ്ഥ AF_INET:
		എങ്കിൽ (*len < വലുപ്പം(*in4))
			തിരികെ -1;
		memset(sa, '\0', വലുപ്പം(*in4));
		*len = വലുപ്പം(*in4);
#ifdef SOCK_HAS_LEN
		in4->sin_len = വലുപ്പം(*in4);
#endif
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, വലുപ്പം(in4->sin_addr));
		നിർത്തുക;
	അവസ്ഥ AF_INET6:
		എങ്കിൽ (*len < വലുപ്പം(*in6))
			തിരികെ -1;
		memset(sa, '\0', വലുപ്പം(*in6));
		*len = വലുപ്പം(*in6);
#ifdef SOCK_HAS_LEN
		in6->sin6_len = വലുപ്പം(*in6);
#endif
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, വലുപ്പം(in6->sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#endif
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
	തിരികെ 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
പൂർണ്ണസംഖ്യ
addr_sa_to_xaddr(ഘടന sockaddr *sa, socklen_t slen, ഘടന xaddr *xa)
{
	ഘടന sockaddr_in *in4 = (ഘടന sockaddr_in *)sa;
	ഘടന sockaddr_in6 *in6 = (ഘടന sockaddr_in6 *)sa;

	memset(xa, '\0', വലുപ്പം(*xa));

	തിരഞ്ഞെടുപ്പ് (sa->sa_family) {
	അവസ്ഥ AF_INET:
		എങ്കിൽ (slen < (socklen_t)വലുപ്പം(*in4))
			തിരികെ -1;
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, വലുപ്പം(xa->v4));
		നിർത്തുക;
	അവസ്ഥ AF_INET6:
		എങ്കിൽ (slen < (socklen_t)വലുപ്പം(*in6))
			തിരികെ -1;
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, വലുപ്പം(xa->v6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#endif
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
addr_invert(ഘടന xaddr *n)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (n == ശൂന്യ)
		തിരികെ -1;

	തിരഞ്ഞെടുപ്പ് (n->af) {
	അവസ്ഥ AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		തിരികെ 0;
	അവസ്ഥ AF_INET6:
		വേണ്ടി (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		തിരികെ 0;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
പൂർണ്ണസംഖ്യ
addr_netmask(പൂർണ്ണസംഖ്യ af, u_int l, ഘടന xaddr *n)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (masklen_valid(af, l) != 0 || n == ശൂന്യ)
		തിരികെ -1;

	memset(n, '\0', വലുപ്പം(*n));
	തിരഞ്ഞെടുപ്പ് (af) {
	അവസ്ഥ AF_INET:
		n->af = AF_INET;
		എങ്കിൽ (l == 0)
			തിരികെ 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		തിരികെ 0;
	അവസ്ഥ AF_INET6:
		n->af = AF_INET6;
		വേണ്ടി (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		എങ്കിൽ (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		തിരികെ 0;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
addr_hostmask(പൂർണ്ണസംഖ്യ af, u_int l, ഘടന xaddr *n)
{
	എങ്കിൽ (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		തിരികെ -1;
	തിരികെ 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
പൂർണ്ണസംഖ്യ
addr_and(ഘടന xaddr *dst, സ്ഥിരം ഘടന xaddr *a, സ്ഥിരം ഘടന xaddr *b)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (dst == ശൂന്യ || a == ശൂന്യ || b == ശൂന്യ || a->af != b->af)
		തിരികെ -1;

	memcpy(dst, a, വലുപ്പം(*dst));
	തിരഞ്ഞെടുപ്പ് (a->af) {
	അവസ്ഥ AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		തിരികെ 0;
	അവസ്ഥ AF_INET6:
		dst->scope_id = a->scope_id;
		വേണ്ടി (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		തിരികെ 0;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
addr_or(ഘടന xaddr *dst, സ്ഥിരം ഘടന xaddr *a, സ്ഥിരം ഘടന xaddr *b)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (dst == ശൂന്യ || a == ശൂന്യ || b == ശൂന്യ || a->af != b->af)
		തിരികെ (-1);

	memcpy(dst, a, വലുപ്പം(*dst));
	തിരഞ്ഞെടുപ്പ് (a->af) {
	അവസ്ഥ AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		തിരികെ (0);
	അവസ്ഥ AF_INET6:
		വേണ്ടി (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		തിരികെ (0);
	സ്ഥിരസ്ഥിതി:
		തിരികെ (-1);
	}
}

പൂർണ്ണസംഖ്യ
addr_cmp(സ്ഥിരം ഘടന xaddr *a, സ്ഥിരം ഘടന xaddr *b)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (a->af != b->af)
		തിരികെ (a->af == AF_INET6 ? 1 : -1);

	തിരഞ്ഞെടുപ്പ് (a->af) {
	അവസ്ഥ AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		എങ്കിൽ (a->v4.s_addr == b->v4.s_addr)
			തിരികെ 0;
		തിരികെ (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	അവസ്ഥ AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		വേണ്ടി (i = 0; i < 16; i++)
			എങ്കിൽ (a->addr8[i] - b->addr8[i] != 0)
				തിരികെ (a->addr8[i] - b->addr8[i]);
		എങ്കിൽ (a->scope_id == b->scope_id)
			തിരികെ (0);
		തിരികെ (a->scope_id > b->scope_id ? 1 : -1);
	സ്ഥിരസ്ഥിതി:
		തിരികെ (-1);
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
addr_is_all0s(സ്ഥിരം ഘടന xaddr *a)
{
	പൂർണ്ണസംഖ്യ i;

	തിരഞ്ഞെടുപ്പ് (a->af) {
	അവസ്ഥ AF_INET:
		തിരികെ (a->v4.s_addr == 0 ? 0 : -1);
	അവസ്ഥ AF_INET6:
		വേണ്ടി (i = 0; i < 4; i++)
			എങ്കിൽ (a->addr32[i] != 0)
				തിരികെ -1;
		തിരികെ 0;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
ശൂന്യം
addr_increment(ഘടന xaddr *a)
{
	പൂർണ്ണസംഖ്യ i;
	uint32_t n;

	തിരഞ്ഞെടുപ്പ് (a->af) {
	അവസ്ഥ AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		നിർത്തുക;
	അവസ്ഥ AF_INET6:
		വേണ്ടി (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			എങ്കിൽ (n != 0)
				നിർത്തുക;
		}
		നിർത്തുക;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
addr_host_is_all0s(സ്ഥിരം ഘടന xaddr *a, u_int masklen)
{
	ഘടന xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, വലുപ്പം(tmp_addr));
	എങ്കിൽ (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		തിരികെ -1;
	എങ്കിൽ (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		തിരികെ -1;
	തിരികെ addr_is_all0s(&tmp_result);
}

#എങ്കിൽ 0
സ്ഥിതം പൂർണ്ണസംഖ്യ
addr_host_to_all0s(ഘടന xaddr *a, u_int masklen)
{
	ഘടന xaddr tmp_mask;

	എങ്കിൽ (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		തിരികെ (-1);
	എങ്കിൽ (addr_and(a, a, &tmp_mask) == -1)
		തിരികെ (-1);
	തിരികെ (0);
}
#endif

പൂർണ്ണസംഖ്യ
addr_host_to_all1s(ഘടന xaddr *a, u_int masklen)
{
	ഘടന xaddr tmp_mask;

	എങ്കിൽ (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		തിരികെ (-1);
	എങ്കിൽ (addr_or(a, a, &tmp_mask) == -1)
		തിരികെ (-1);
	തിരികെ (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
പൂർണ്ണസംഖ്യ
addr_pton(സ്ഥിരം അക്ഷരം *p, ഘടന xaddr *n)
{
	ഘടന addrinfo hints, *ai;

	memset(&hints, '\0', വലുപ്പം(hints));
	hints.ai_flags = AI_NUMERICHOST;

	എങ്കിൽ (p == ശൂന്യ || getaddrinfo(p, ശൂന്യ, &hints, &ai) != 0)
		തിരികെ -1;

	എങ്കിൽ (ai == ശൂന്യ)
		തിരികെ -1;

	എങ്കിൽ (ai->ai_addr == ശൂന്യ) {
		freeaddrinfo(ai);
		തിരികെ -1;
	}

	എങ്കിൽ (n != ശൂന്യ && addr_sa_to_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		തിരികെ -1;
	}

	freeaddrinfo(ai);
	തിരികെ 0;
}

#എങ്കിൽ 0
സ്ഥിതം പൂർണ്ണസംഖ്യ
addr_sa_pton(സ്ഥിരം അക്ഷരം *h, സ്ഥിരം അക്ഷരം *s, ഘടന sockaddr *sa, socklen_t slen)
{
	ഘടന addrinfo hints, *ai;

	memset(&hints, '\0', വലുപ്പം(hints));
	hints.ai_flags = AI_NUMERICHOST;

	എങ്കിൽ (h == ശൂന്യ || getaddrinfo(h, s, &hints, &ai) != 0)
		തിരികെ -1;

	എങ്കിൽ (ai == ശൂന്യ)
		തിരികെ -1;

	എങ്കിൽ (ai->ai_addr == ശൂന്യ) {
		freeaddrinfo(ai);
		തിരികെ -1;
	}

	എങ്കിൽ (sa != ശൂന്യ) {
		എങ്കിൽ (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			തിരികെ -1;
		}
		memcpy(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	തിരികെ 0;
}
#endif

പൂർണ്ണസംഖ്യ
addr_ntop(സ്ഥിരം ഘടന xaddr *n, അക്ഷരം *p, size_t len)
{
	ഘടന sockaddr_storage ss;
	socklen_t slen = വലുപ്പം(ss);

	എങ്കിൽ (addr_xaddr_to_sa(n, _SA(&ss), &slen, 0) == -1)
		തിരികെ -1;
	എങ്കിൽ (p == ശൂന്യ || len == 0)
		തിരികെ -1;
	എങ്കിൽ (getnameinfo(_SA(&ss), slen, p, len, ശൂന്യ, 0,
	    NI_NUMERICHOST) != 0)
		തിരികെ -1;

	തിരികെ 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
പൂർണ്ണസംഖ്യ
addr_pton_cidr(സ്ഥിരം അക്ഷരം *p, ഘടന xaddr *n, u_int *l)
{
	ഘടന xaddr tmp;
	u_int masklen = 999;
	അക്ഷരം addrbuf[64], *mp;
	സ്ഥിരം അക്ഷരം *errstr;

	/* Don't modify argument */
	എങ്കിൽ (p == ശൂന്യ || strlcpy(addrbuf, p, വലുപ്പം(addrbuf)) >= വലുപ്പം(addrbuf))
		തിരികെ -1;

	എങ്കിൽ ((mp = strchr(addrbuf, '/')) != ശൂന്യ) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, INT_MAX, &errstr);
		എങ്കിൽ (errstr)
			തിരികെ -1;
	}

	എങ്കിൽ (addr_pton(addrbuf, &tmp) == -1)
		തിരികെ -1;

	എങ്കിൽ (mp == ശൂന്യ)
		masklen = addr_unicast_masklen(tmp.af);
	എങ്കിൽ (masklen_valid(tmp.af, masklen) == -1)
		തിരികെ -2;
	എങ്കിൽ (addr_host_is_all0s(&tmp, masklen) != 0)
		തിരികെ -2;

	എങ്കിൽ (n != ശൂന്യ)
		memcpy(n, &tmp, വലുപ്പം(*n));
	എങ്കിൽ (l != ശൂന്യ)
		*l = masklen;

	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
addr_netmatch(സ്ഥിരം ഘടന xaddr *host, സ്ഥിരം ഘടന xaddr *net, u_int masklen)
{
	ഘടന xaddr tmp_mask, tmp_result;

	എങ്കിൽ (host->af != net->af)
		തിരികെ -1;

	എങ്കിൽ (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		തിരികെ -1;
	എങ്കിൽ (addr_and(&tmp_result, host, &tmp_mask) == -1)
		തിരികെ -1;
	തിരികെ addr_cmp(&tmp_result, net);
}
