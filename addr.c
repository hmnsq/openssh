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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <arpa/inet.h>

#అన్తర్భావ <netdb.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "addr.h"

#నిర్వచించు _SA(x)	((నిర్మాణం sockaddr *)(x))

స్థిర పూర్ణాంకం
addr_unicast_masklen(పూర్ణాంకం af)
{
	ఎంపిక (af) {
	స్థితి AF_INET:
		తిరిగి 32;
	స్థితి AF_INET6:
		తిరిగి 128;
	అప్రమేయ:
		తిరిగి -1;
	}
}

స్థిర అంతఃవరుస పూర్ణాంకం
masklen_valid(పూర్ణాంకం af, u_int masklen)
{
	ఎంపిక (af) {
	స్థితి AF_INET:
		తిరిగి masklen <= 32 ? 0 : -1;
	స్థితి AF_INET6:
		తిరిగి masklen <= 128 ? 0 : -1;
	అప్రమేయ:
		తిరిగి -1;
	}
}

స్థిర పూర్ణాంకం
addr_xaddr_గమ్యం_sa(స్థిరరాశి నిర్మాణం xaddr *xa, నిర్మాణం sockaddr *sa, socklen_t *len,
    uint16_t పోర్టు)
{
	నిర్మాణం sockaddr_in *in4 = (నిర్మాణం sockaddr_in *)sa;
	నిర్మాణం sockaddr_in6 *in6 = (నిర్మాణం sockaddr_in6 *)sa;

	ఒకవేళ (xa == ఖాళీ || sa == ఖాళీ || len == ఖాళీ)
		తిరిగి -1;

	ఎంపిక (xa->af) {
	స్థితి AF_INET:
		ఒకవేళ (*len < పరిమాణం(*in4))
			తిరిగి -1;
		memset(sa, '\0', పరిమాణం(*in4));
		*len = పరిమాణం(*in4);
#నిర్వచితమైతే SOCK_HAS_LEN
		in4->sin_len = పరిమాణం(*in4);
#అయితే_ముగింపు
		in4->sin_family = AF_INET;
		in4->sin_port = htons(పోర్టు);
		జ్ఞాపకం_నకలు(&in4->sin_addr, &xa->v4, పరిమాణం(in4->sin_addr));
		ఆపు;
	స్థితి AF_INET6:
		ఒకవేళ (*len < పరిమాణం(*in6))
			తిరిగి -1;
		memset(sa, '\0', పరిమాణం(*in6));
		*len = పరిమాణం(*in6);
#నిర్వచితమైతే SOCK_HAS_LEN
		in6->sin6_len = పరిమాణం(*in6);
#అయితే_ముగింపు
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(పోర్టు);
		జ్ఞాపకం_నకలు(&in6->sin6_addr, &xa->v6, పరిమాణం(in6->sin6_addr));
#నిర్వచితమైతే HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#అయితే_ముగింపు
		ఆపు;
	అప్రమేయ:
		తిరిగి -1;
	}
	తిరిగి 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
పూర్ణాంకం
addr_sa_గమ్యం_xaddr(నిర్మాణం sockaddr *sa, socklen_t slen, నిర్మాణం xaddr *xa)
{
	నిర్మాణం sockaddr_in *in4 = (నిర్మాణం sockaddr_in *)sa;
	నిర్మాణం sockaddr_in6 *in6 = (నిర్మాణం sockaddr_in6 *)sa;

	memset(xa, '\0', పరిమాణం(*xa));

	ఎంపిక (sa->sa_family) {
	స్థితి AF_INET:
		ఒకవేళ (slen < (socklen_t)పరిమాణం(*in4))
			తిరిగి -1;
		xa->af = AF_INET;
		జ్ఞాపకం_నకలు(&xa->v4, &in4->sin_addr, పరిమాణం(xa->v4));
		ఆపు;
	స్థితి AF_INET6:
		ఒకవేళ (slen < (socklen_t)పరిమాణం(*in6))
			తిరిగి -1;
		xa->af = AF_INET6;
		జ్ఞాపకం_నకలు(&xa->v6, &in6->sin6_addr, పరిమాణం(xa->v6));
#నిర్వచితమైతే HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#అయితే_ముగింపు
		ఆపు;
	అప్రమేయ:
		తిరిగి -1;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
addr_invert(నిర్మాణం xaddr *n)
{
	పూర్ణాంకం i;

	ఒకవేళ (n == ఖాళీ)
		తిరిగి -1;

	ఎంపిక (n->af) {
	స్థితి AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		తిరిగి 0;
	స్థితి AF_INET6:
		కొరకు (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		తిరిగి 0;
	అప్రమేయ:
		తిరిగి -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
పూర్ణాంకం
addr_netmask(పూర్ణాంకం af, u_int l, నిర్మాణం xaddr *n)
{
	పూర్ణాంకం i;

	ఒకవేళ (masklen_valid(af, l) != 0 || n == ఖాళీ)
		తిరిగి -1;

	memset(n, '\0', పరిమాణం(*n));
	ఎంపిక (af) {
	స్థితి AF_INET:
		n->af = AF_INET;
		ఒకవేళ (l == 0)
			తిరిగి 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		తిరిగి 0;
	స్థితి AF_INET6:
		n->af = AF_INET6;
		కొరకు (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		ఒకవేళ (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		తిరిగి 0;
	అప్రమేయ:
		తిరిగి -1;
	}
}

స్థిర పూర్ణాంకం
addr_hostmask(పూర్ణాంకం af, u_int l, నిర్మాణం xaddr *n)
{
	ఒకవేళ (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		తిరిగి -1;
	తిరిగి 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
పూర్ణాంకం
addr_and(నిర్మాణం xaddr *dst, స్థిరరాశి నిర్మాణం xaddr *a, స్థిరరాశి నిర్మాణం xaddr *b)
{
	పూర్ణాంకం i;

	ఒకవేళ (dst == ఖాళీ || a == ఖాళీ || b == ఖాళీ || a->af != b->af)
		తిరిగి -1;

	జ్ఞాపకం_నకలు(dst, a, పరిమాణం(*dst));
	ఎంపిక (a->af) {
	స్థితి AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		తిరిగి 0;
	స్థితి AF_INET6:
		dst->scope_id = a->scope_id;
		కొరకు (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		తిరిగి 0;
	అప్రమేయ:
		తిరిగి -1;
	}
}

స్థిర పూర్ణాంకం
addr_or(నిర్మాణం xaddr *dst, స్థిరరాశి నిర్మాణం xaddr *a, స్థిరరాశి నిర్మాణం xaddr *b)
{
	పూర్ణాంకం i;

	ఒకవేళ (dst == ఖాళీ || a == ఖాళీ || b == ఖాళీ || a->af != b->af)
		తిరిగి (-1);

	జ్ఞాపకం_నకలు(dst, a, పరిమాణం(*dst));
	ఎంపిక (a->af) {
	స్థితి AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		తిరిగి (0);
	స్థితి AF_INET6:
		కొరకు (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		తిరిగి (0);
	అప్రమేయ:
		తిరిగి (-1);
	}
}

పూర్ణాంకం
addr_cmp(స్థిరరాశి నిర్మాణం xaddr *a, స్థిరరాశి నిర్మాణం xaddr *b)
{
	పూర్ణాంకం i;

	ఒకవేళ (a->af != b->af)
		తిరిగి (a->af == AF_INET6 ? 1 : -1);

	ఎంపిక (a->af) {
	స్థితి AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		ఒకవేళ (a->v4.s_addr == b->v4.s_addr)
			తిరిగి 0;
		తిరిగి (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	స్థితి AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		కొరకు (i = 0; i < 16; i++)
			ఒకవేళ (a->addr8[i] - b->addr8[i] != 0)
				తిరిగి (a->addr8[i] - b->addr8[i]);
		ఒకవేళ (a->scope_id == b->scope_id)
			తిరిగి (0);
		తిరిగి (a->scope_id > b->scope_id ? 1 : -1);
	అప్రమేయ:
		తిరిగి (-1);
	}
}

స్థిర పూర్ణాంకం
addr_is_all0s(స్థిరరాశి నిర్మాణం xaddr *a)
{
	పూర్ణాంకం i;

	ఎంపిక (a->af) {
	స్థితి AF_INET:
		తిరిగి (a->v4.s_addr == 0 ? 0 : -1);
	స్థితి AF_INET6:
		కొరకు (i = 0; i < 4; i++)
			ఒకవేళ (a->addr32[i] != 0)
				తిరిగి -1;
		తిరిగి 0;
	అప్రమేయ:
		తిరిగి -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
శూన్య
addr_increment(నిర్మాణం xaddr *a)
{
	పూర్ణాంకం i;
	uint32_t n;

	ఎంపిక (a->af) {
	స్థితి AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		ఆపు;
	స్థితి AF_INET6:
		కొరకు (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			ఒకవేళ (n != 0)
				ఆపు;
		}
		ఆపు;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
స్థిర పూర్ణాంకం
addr_host_is_all0s(స్థిరరాశి నిర్మాణం xaddr *a, u_int masklen)
{
	నిర్మాణం xaddr tmp_addr, tmp_ముసుగు, tmp_ఫలితం;

	జ్ఞాపకం_నకలు(&tmp_addr, a, పరిమాణం(tmp_addr));
	ఒకవేళ (addr_hostmask(a->af, masklen, &tmp_ముసుగు) == -1)
		తిరిగి -1;
	ఒకవేళ (addr_and(&tmp_ఫలితం, &tmp_addr, &tmp_ముసుగు) == -1)
		తిరిగి -1;
	తిరిగి addr_is_all0s(&tmp_ఫలితం);
}

#ఒకవేళ 0
స్థిర పూర్ణాంకం
addr_host_గమ్యం_all0s(నిర్మాణం xaddr *a, u_int masklen)
{
	నిర్మాణం xaddr tmp_ముసుగు;

	ఒకవేళ (addr_netmask(a->af, masklen, &tmp_ముసుగు) == -1)
		తిరిగి (-1);
	ఒకవేళ (addr_and(a, a, &tmp_ముసుగు) == -1)
		తిరిగి (-1);
	తిరిగి (0);
}
#అయితే_ముగింపు

పూర్ణాంకం
addr_host_గమ్యం_all1s(నిర్మాణం xaddr *a, u_int masklen)
{
	నిర్మాణం xaddr tmp_ముసుగు;

	ఒకవేళ (addr_hostmask(a->af, masklen, &tmp_ముసుగు) == -1)
		తిరిగి (-1);
	ఒకవేళ (addr_or(a, a, &tmp_ముసుగు) == -1)
		తిరిగి (-1);
	తిరిగి (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
పూర్ణాంకం
addr_pton(స్థిరరాశి అక్షరం *p, నిర్మాణం xaddr *n)
{
	నిర్మాణం addrinfo hints, *ai;

	memset(&hints, '\0', పరిమాణం(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ఒకవేళ (p == ఖాళీ || getaddrinfo(p, ఖాళీ, &hints, &ai) != 0)
		తిరిగి -1;

	ఒకవేళ (ai == ఖాళీ)
		తిరిగి -1;

	ఒకవేళ (ai->ai_addr == ఖాళీ) {
		freeaddrinfo(ai);
		తిరిగి -1;
	}

	ఒకవేళ (n != ఖాళీ && addr_sa_గమ్యం_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		తిరిగి -1;
	}

	freeaddrinfo(ai);
	తిరిగి 0;
}

#ఒకవేళ 0
స్థిర పూర్ణాంకం
addr_sa_pton(స్థిరరాశి అక్షరం *h, స్థిరరాశి అక్షరం *s, నిర్మాణం sockaddr *sa, socklen_t slen)
{
	నిర్మాణం addrinfo hints, *ai;

	memset(&hints, '\0', పరిమాణం(hints));
	hints.ai_flags = AI_NUMERICHOST;

	ఒకవేళ (h == ఖాళీ || getaddrinfo(h, s, &hints, &ai) != 0)
		తిరిగి -1;

	ఒకవేళ (ai == ఖాళీ)
		తిరిగి -1;

	ఒకవేళ (ai->ai_addr == ఖాళీ) {
		freeaddrinfo(ai);
		తిరిగి -1;
	}

	ఒకవేళ (sa != ఖాళీ) {
		ఒకవేళ (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			తిరిగి -1;
		}
		జ్ఞాపకం_నకలు(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	తిరిగి 0;
}
#అయితే_ముగింపు

పూర్ణాంకం
addr_ntop(స్థిరరాశి నిర్మాణం xaddr *n, అక్షరం *p, కొలత_t len)
{
	నిర్మాణం sockaddr_storage ss;
	socklen_t slen = పరిమాణం(ss);

	ఒకవేళ (addr_xaddr_గమ్యం_sa(n, _SA(&ss), &slen, 0) == -1)
		తిరిగి -1;
	ఒకవేళ (p == ఖాళీ || len == 0)
		తిరిగి -1;
	ఒకవేళ (getnameinfo(_SA(&ss), slen, p, len, ఖాళీ, 0,
	    NI_NUMERICHOST) != 0)
		తిరిగి -1;

	తిరిగి 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
పూర్ణాంకం
addr_pton_cidr(స్థిరరాశి అక్షరం *p, నిర్మాణం xaddr *n, u_int *l)
{
	నిర్మాణం xaddr tmp;
	u_int masklen = 999;
	అక్షరం addrbuf[64], *mp;
	స్థిరరాశి అక్షరం *errstr;

	/* Don't modify argument */
	ఒకవేళ (p == ఖాళీ || strlcpy(addrbuf, p, పరిమాణం(addrbuf)) >= పరిమాణం(addrbuf))
		తిరిగి -1;

	ఒకవేళ ((mp = strchr(addrbuf, '/')) != ఖాళీ) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, గరిష్ఠ_పూర్ణాంకం, &errstr);
		ఒకవేళ (errstr)
			తిరిగి -1;
	}

	ఒకవేళ (addr_pton(addrbuf, &tmp) == -1)
		తిరిగి -1;

	ఒకవేళ (mp == ఖాళీ)
		masklen = addr_unicast_masklen(tmp.af);
	ఒకవేళ (masklen_valid(tmp.af, masklen) == -1)
		తిరిగి -2;
	ఒకవేళ (addr_host_is_all0s(&tmp, masklen) != 0)
		తిరిగి -2;

	ఒకవేళ (n != ఖాళీ)
		జ్ఞాపకం_నకలు(n, &tmp, పరిమాణం(*n));
	ఒకవేళ (l != ఖాళీ)
		*l = masklen;

	తిరిగి 0;
}

పూర్ణాంకం
addr_netmatch(స్థిరరాశి నిర్మాణం xaddr *host, స్థిరరాశి నిర్మాణం xaddr *net, u_int masklen)
{
	నిర్మాణం xaddr tmp_ముసుగు, tmp_ఫలితం;

	ఒకవేళ (host->af != net->af)
		తిరిగి -1;

	ఒకవేళ (addr_netmask(host->af, masklen, &tmp_ముసుగు) == -1)
		తిరిగి -1;
	ఒకవేళ (addr_and(&tmp_ఫలితం, host, &tmp_ముసుగు) == -1)
		తిరిగి -1;
	తిరిగి addr_cmp(&tmp_ఫలితం, net);
}
