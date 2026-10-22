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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <netinet/in.h>
#شامل <arpa/inet.h>

#شامل <netdb.h>
#شامل <string.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <limits.h>

#شامل "addr.h"

#تعریف_کرو _SA(x)	((ساخت sockaddr *)(x))

ساکن صحیح
addr_unicast_masklen(صحیح af)
{
	انتخاب (af) {
	حالت AF_INET:
		واپس 32;
	حالت AF_INET6:
		واپس 128;
	طےشدہ:
		واپس -1;
	}
}

ساکن اندرونی صحیح
masklen_valid(صحیح af, u_int masklen)
{
	انتخاب (af) {
	حالت AF_INET:
		واپس masklen <= 32 ? 0 : -1;
	حالت AF_INET6:
		واپس masklen <= 128 ? 0 : -1;
	طےشدہ:
		واپس -1;
	}
}

ساکن صحیح
addr_xaddr_مقصد_sa(ثابت ساخت xaddr *xa, ساخت sockaddr *sa, socklen_t *len,
    uint16_t پورٹ)
{
	ساخت sockaddr_in *in4 = (ساخت sockaddr_in *)sa;
	ساخت sockaddr_in6 *in6 = (ساخت sockaddr_in6 *)sa;

	اگر (xa == تہی || sa == تہی || len == تہی)
		واپس -1;

	انتخاب (xa->af) {
	حالت AF_INET:
		اگر (*len < حجم(*in4))
			واپس -1;
		memset(sa, '\0', حجم(*in4));
		*len = حجم(*in4);
#اگر_تعریف_شدہ SOCK_HAS_LEN
		in4->sin_len = حجم(*in4);
#اگر_ختم
		in4->sin_family = AF_INET;
		in4->sin_port = htons(پورٹ);
		حافظہ_نقل(&in4->sin_addr, &xa->v4, حجم(in4->sin_addr));
		توڑو;
	حالت AF_INET6:
		اگر (*len < حجم(*in6))
			واپس -1;
		memset(sa, '\0', حجم(*in6));
		*len = حجم(*in6);
#اگر_تعریف_شدہ SOCK_HAS_LEN
		in6->sin6_len = حجم(*in6);
#اگر_ختم
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(پورٹ);
		حافظہ_نقل(&in6->sin6_addr, &xa->v6, حجم(in6->sin6_addr));
#اگر_تعریف_شدہ HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#اگر_ختم
		توڑو;
	طےشدہ:
		واپس -1;
	}
	واپس 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
صحیح
addr_sa_مقصد_xaddr(ساخت sockaddr *sa, socklen_t slen, ساخت xaddr *xa)
{
	ساخت sockaddr_in *in4 = (ساخت sockaddr_in *)sa;
	ساخت sockaddr_in6 *in6 = (ساخت sockaddr_in6 *)sa;

	memset(xa, '\0', حجم(*xa));

	انتخاب (sa->sa_family) {
	حالت AF_INET:
		اگر (slen < (socklen_t)حجم(*in4))
			واپس -1;
		xa->af = AF_INET;
		حافظہ_نقل(&xa->v4, &in4->sin_addr, حجم(xa->v4));
		توڑو;
	حالت AF_INET6:
		اگر (slen < (socklen_t)حجم(*in6))
			واپس -1;
		xa->af = AF_INET6;
		حافظہ_نقل(&xa->v6, &in6->sin6_addr, حجم(xa->v6));
#اگر_تعریف_شدہ HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#اگر_ختم
		توڑو;
	طےشدہ:
		واپس -1;
	}

	واپس 0;
}

ساکن صحیح
addr_invert(ساخت xaddr *n)
{
	صحیح i;

	اگر (n == تہی)
		واپس -1;

	انتخاب (n->af) {
	حالت AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		واپس 0;
	حالت AF_INET6:
		برائے (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		واپس 0;
	طےشدہ:
		واپس -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
صحیح
addr_netmask(صحیح af, u_int l, ساخت xaddr *n)
{
	صحیح i;

	اگر (masklen_valid(af, l) != 0 || n == تہی)
		واپس -1;

	memset(n, '\0', حجم(*n));
	انتخاب (af) {
	حالت AF_INET:
		n->af = AF_INET;
		اگر (l == 0)
			واپس 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		واپس 0;
	حالت AF_INET6:
		n->af = AF_INET6;
		برائے (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		اگر (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		واپس 0;
	طےشدہ:
		واپس -1;
	}
}

ساکن صحیح
addr_hostmask(صحیح af, u_int l, ساخت xaddr *n)
{
	اگر (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		واپس -1;
	واپس 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
صحیح
addr_and(ساخت xaddr *dst, ثابت ساخت xaddr *a, ثابت ساخت xaddr *b)
{
	صحیح i;

	اگر (dst == تہی || a == تہی || b == تہی || a->af != b->af)
		واپس -1;

	حافظہ_نقل(dst, a, حجم(*dst));
	انتخاب (a->af) {
	حالت AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		واپس 0;
	حالت AF_INET6:
		dst->scope_id = a->scope_id;
		برائے (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		واپس 0;
	طےشدہ:
		واپس -1;
	}
}

ساکن صحیح
addr_or(ساخت xaddr *dst, ثابت ساخت xaddr *a, ثابت ساخت xaddr *b)
{
	صحیح i;

	اگر (dst == تہی || a == تہی || b == تہی || a->af != b->af)
		واپس (-1);

	حافظہ_نقل(dst, a, حجم(*dst));
	انتخاب (a->af) {
	حالت AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		واپس (0);
	حالت AF_INET6:
		برائے (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		واپس (0);
	طےشدہ:
		واپس (-1);
	}
}

صحیح
addr_cmp(ثابت ساخت xaddr *a, ثابت ساخت xaddr *b)
{
	صحیح i;

	اگر (a->af != b->af)
		واپس (a->af == AF_INET6 ? 1 : -1);

	انتخاب (a->af) {
	حالت AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		اگر (a->v4.s_addr == b->v4.s_addr)
			واپس 0;
		واپس (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	حالت AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		برائے (i = 0; i < 16; i++)
			اگر (a->addr8[i] - b->addr8[i] != 0)
				واپس (a->addr8[i] - b->addr8[i]);
		اگر (a->scope_id == b->scope_id)
			واپس (0);
		واپس (a->scope_id > b->scope_id ? 1 : -1);
	طےشدہ:
		واپس (-1);
	}
}

ساکن صحیح
addr_is_all0s(ثابت ساخت xaddr *a)
{
	صحیح i;

	انتخاب (a->af) {
	حالت AF_INET:
		واپس (a->v4.s_addr == 0 ? 0 : -1);
	حالت AF_INET6:
		برائے (i = 0; i < 4; i++)
			اگر (a->addr32[i] != 0)
				واپس -1;
		واپس 0;
	طےشدہ:
		واپس -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
خالی
addr_increment(ساخت xaddr *a)
{
	صحیح i;
	uint32_t n;

	انتخاب (a->af) {
	حالت AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		توڑو;
	حالت AF_INET6:
		برائے (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			اگر (n != 0)
				توڑو;
		}
		توڑو;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
ساکن صحیح
addr_host_is_all0s(ثابت ساخت xaddr *a, u_int masklen)
{
	ساخت xaddr tmp_addr, tmp_نقاب, tmp_نتیجہ;

	حافظہ_نقل(&tmp_addr, a, حجم(tmp_addr));
	اگر (addr_hostmask(a->af, masklen, &tmp_نقاب) == -1)
		واپس -1;
	اگر (addr_and(&tmp_نتیجہ, &tmp_addr, &tmp_نقاب) == -1)
		واپس -1;
	واپس addr_is_all0s(&tmp_نتیجہ);
}

#اگر 0
ساکن صحیح
addr_host_مقصد_all0s(ساخت xaddr *a, u_int masklen)
{
	ساخت xaddr tmp_نقاب;

	اگر (addr_netmask(a->af, masklen, &tmp_نقاب) == -1)
		واپس (-1);
	اگر (addr_and(a, a, &tmp_نقاب) == -1)
		واپس (-1);
	واپس (0);
}
#اگر_ختم

صحیح
addr_host_مقصد_all1s(ساخت xaddr *a, u_int masklen)
{
	ساخت xaddr tmp_نقاب;

	اگر (addr_hostmask(a->af, masklen, &tmp_نقاب) == -1)
		واپس (-1);
	اگر (addr_or(a, a, &tmp_نقاب) == -1)
		واپس (-1);
	واپس (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
صحیح
addr_pton(ثابت حرف *p, ساخت xaddr *n)
{
	ساخت addrinfo hints, *ai;

	memset(&hints, '\0', حجم(hints));
	hints.ai_flags = AI_NUMERICHOST;

	اگر (p == تہی || getaddrinfo(p, تہی, &hints, &ai) != 0)
		واپس -1;

	اگر (ai == تہی)
		واپس -1;

	اگر (ai->ai_addr == تہی) {
		freeaddrinfo(ai);
		واپس -1;
	}

	اگر (n != تہی && addr_sa_مقصد_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		واپس -1;
	}

	freeaddrinfo(ai);
	واپس 0;
}

#اگر 0
ساکن صحیح
addr_sa_pton(ثابت حرف *h, ثابت حرف *s, ساخت sockaddr *sa, socklen_t slen)
{
	ساخت addrinfo hints, *ai;

	memset(&hints, '\0', حجم(hints));
	hints.ai_flags = AI_NUMERICHOST;

	اگر (h == تہی || getaddrinfo(h, s, &hints, &ai) != 0)
		واپس -1;

	اگر (ai == تہی)
		واپس -1;

	اگر (ai->ai_addr == تہی) {
		freeaddrinfo(ai);
		واپس -1;
	}

	اگر (sa != تہی) {
		اگر (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			واپس -1;
		}
		حافظہ_نقل(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	واپس 0;
}
#اگر_ختم

صحیح
addr_ntop(ثابت ساخت xaddr *n, حرف *p, سائز_t len)
{
	ساخت sockaddr_storage ss;
	socklen_t slen = حجم(ss);

	اگر (addr_xaddr_مقصد_sa(n, _SA(&ss), &slen, 0) == -1)
		واپس -1;
	اگر (p == تہی || len == 0)
		واپس -1;
	اگر (getnameinfo(_SA(&ss), slen, p, len, تہی, 0,
	    NI_NUMERICHOST) != 0)
		واپس -1;

	واپس 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
صحیح
addr_pton_cidr(ثابت حرف *p, ساخت xaddr *n, u_int *l)
{
	ساخت xaddr tmp;
	u_int masklen = 999;
	حرف addrbuf[64], *mp;
	ثابت حرف *errstr;

	/* Don't modify argument */
	اگر (p == تہی || strlcpy(addrbuf, p, حجم(addrbuf)) >= حجم(addrbuf))
		واپس -1;

	اگر ((mp = strchr(addrbuf, '/')) != تہی) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, زیادہ_سے_زیادہ_عدد, &errstr);
		اگر (errstr)
			واپس -1;
	}

	اگر (addr_pton(addrbuf, &tmp) == -1)
		واپس -1;

	اگر (mp == تہی)
		masklen = addr_unicast_masklen(tmp.af);
	اگر (masklen_valid(tmp.af, masklen) == -1)
		واپس -2;
	اگر (addr_host_is_all0s(&tmp, masklen) != 0)
		واپس -2;

	اگر (n != تہی)
		حافظہ_نقل(n, &tmp, حجم(*n));
	اگر (l != تہی)
		*l = masklen;

	واپس 0;
}

صحیح
addr_netmatch(ثابت ساخت xaddr *host, ثابت ساخت xaddr *net, u_int masklen)
{
	ساخت xaddr tmp_نقاب, tmp_نتیجہ;

	اگر (host->af != net->af)
		واپس -1;

	اگر (addr_netmask(host->af, masklen, &tmp_نقاب) == -1)
		واپس -1;
	اگر (addr_and(&tmp_نتیجہ, host, &tmp_نقاب) == -1)
		واپس -1;
	واپس addr_cmp(&tmp_نتیجہ, net);
}
