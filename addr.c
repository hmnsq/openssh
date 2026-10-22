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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <netdb.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "addr.h"

#परिभाषय _SA(x)	((संरचना sockaddr *)(x))

स्थिर पूर्णाङ्क
addr_unicast_masklen(पूर्णाङ्क af)
{
	विकल्प (af) {
	पक्ष AF_INET:
		प्रत्यागम 32;
	पक्ष AF_INET6:
		प्रत्यागम 128;
	स्वभाव:
		प्रत्यागम -1;
	}
}

स्थिर अन्तःस्थ पूर्णाङ्क
masklen_valid(पूर्णाङ्क af, u_int masklen)
{
	विकल्प (af) {
	पक्ष AF_INET:
		प्रत्यागम masklen <= 32 ? 0 : -1;
	पक्ष AF_INET6:
		प्रत्यागम masklen <= 128 ? 0 : -1;
	स्वभाव:
		प्रत्यागम -1;
	}
}

स्थिर पूर्णाङ्क
addr_xaddr_गन्तव्यम्_sa(ध्रुव संरचना xaddr *xa, संरचना sockaddr *sa, socklen_t *len,
    uint16_t पत्तनम्)
{
	संरचना sockaddr_in *in4 = (संरचना sockaddr_in *)sa;
	संरचना sockaddr_in6 *in6 = (संरचना sockaddr_in6 *)sa;

	यदि (xa == रिक्त || sa == रिक्त || len == रिक्त)
		प्रत्यागम -1;

	विकल्प (xa->af) {
	पक्ष AF_INET:
		यदि (*len < परिमाण(*in4))
			प्रत्यागम -1;
		स्मृतिं_पूरय(sa, '\0', परिमाण(*in4));
		*len = परिमाण(*in4);
#यदि_परिभाषितम् SOCK_HAS_LEN
		in4->sin_len = परिमाण(*in4);
#यदि_अन्तः
		in4->sin_family = AF_INET;
		in4->sin_port = htons(पत्तनम्);
		स्मृतिं_प्रतिलिख(&in4->sin_addr, &xa->v4, परिमाण(in4->sin_addr));
		भङ्ग;
	पक्ष AF_INET6:
		यदि (*len < परिमाण(*in6))
			प्रत्यागम -1;
		स्मृतिं_पूरय(sa, '\0', परिमाण(*in6));
		*len = परिमाण(*in6);
#यदि_परिभाषितम् SOCK_HAS_LEN
		in6->sin6_len = परिमाण(*in6);
#यदि_अन्तः
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(पत्तनम्);
		स्मृतिं_प्रतिलिख(&in6->sin6_addr, &xa->v6, परिमाण(in6->sin6_addr));
#यदि_परिभाषितम् HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		in6->sin6_scope_id = xa->scope_id;
#यदि_अन्तः
		भङ्ग;
	स्वभाव:
		प्रत्यागम -1;
	}
	प्रत्यागम 0;
}

/*
 * Convert struct sockaddr to struct xaddr
 * Returns 0 on success, -1 on failure.
 */
पूर्णाङ्क
addr_sa_गन्तव्यम्_xaddr(संरचना sockaddr *sa, socklen_t slen, संरचना xaddr *xa)
{
	संरचना sockaddr_in *in4 = (संरचना sockaddr_in *)sa;
	संरचना sockaddr_in6 *in6 = (संरचना sockaddr_in6 *)sa;

	स्मृतिं_पूरय(xa, '\0', परिमाण(*xa));

	विकल्प (sa->sa_family) {
	पक्ष AF_INET:
		यदि (slen < (socklen_t)परिमाण(*in4))
			प्रत्यागम -1;
		xa->af = AF_INET;
		स्मृतिं_प्रतिलिख(&xa->v4, &in4->sin_addr, परिमाण(xa->v4));
		भङ्ग;
	पक्ष AF_INET6:
		यदि (slen < (socklen_t)परिमाण(*in6))
			प्रत्यागम -1;
		xa->af = AF_INET6;
		स्मृतिं_प्रतिलिख(&xa->v6, &in6->sin6_addr, परिमाण(xa->v6));
#यदि_परिभाषितम् HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID
		xa->scope_id = in6->sin6_scope_id;
#यदि_अन्तः
		भङ्ग;
	स्वभाव:
		प्रत्यागम -1;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
addr_invert(संरचना xaddr *n)
{
	पूर्णाङ्क i;

	यदि (n == रिक्त)
		प्रत्यागम -1;

	विकल्प (n->af) {
	पक्ष AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		प्रत्यागम 0;
	पक्ष AF_INET6:
		प्रति (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		प्रत्यागम 0;
	स्वभाव:
		प्रत्यागम -1;
	}
}

/*
 * Calculate a netmask of length 'l' for address family 'af' and
 * store it in 'n'.
 * Returns 0 on success, -1 on failure.
 */
पूर्णाङ्क
addr_netmask(पूर्णाङ्क af, u_int l, संरचना xaddr *n)
{
	पूर्णाङ्क i;

	यदि (masklen_valid(af, l) != 0 || n == रिक्त)
		प्रत्यागम -1;

	स्मृतिं_पूरय(n, '\0', परिमाण(*n));
	विकल्प (af) {
	पक्ष AF_INET:
		n->af = AF_INET;
		यदि (l == 0)
			प्रत्यागम 0;
		n->v4.s_addr = htonl((0xffffffff << (32 - l)) & 0xffffffff);
		प्रत्यागम 0;
	पक्ष AF_INET6:
		n->af = AF_INET6;
		प्रति (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		यदि (i < 4 && l != 0)
			n->addr32[i] = htonl((0xffffffff << (32 - l)) &
			    0xffffffff);
		प्रत्यागम 0;
	स्वभाव:
		प्रत्यागम -1;
	}
}

स्थिर पूर्णाङ्क
addr_hostmask(पूर्णाङ्क af, u_int l, संरचना xaddr *n)
{
	यदि (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		प्रत्यागम -1;
	प्रत्यागम 0;
}

/*
 * Perform logical AND of addresses 'a' and 'b', storing result in 'dst'.
 * Returns 0 on success, -1 on failure.
 */
पूर्णाङ्क
addr_and(संरचना xaddr *dst, ध्रुव संरचना xaddr *a, ध्रुव संरचना xaddr *b)
{
	पूर्णाङ्क i;

	यदि (dst == रिक्त || a == रिक्त || b == रिक्त || a->af != b->af)
		प्रत्यागम -1;

	स्मृतिं_प्रतिलिख(dst, a, परिमाण(*dst));
	विकल्प (a->af) {
	पक्ष AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		प्रत्यागम 0;
	पक्ष AF_INET6:
		dst->scope_id = a->scope_id;
		प्रति (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		प्रत्यागम 0;
	स्वभाव:
		प्रत्यागम -1;
	}
}

स्थिर पूर्णाङ्क
addr_or(संरचना xaddr *dst, ध्रुव संरचना xaddr *a, ध्रुव संरचना xaddr *b)
{
	पूर्णाङ्क i;

	यदि (dst == रिक्त || a == रिक्त || b == रिक्त || a->af != b->af)
		प्रत्यागम (-1);

	स्मृतिं_प्रतिलिख(dst, a, परिमाण(*dst));
	विकल्प (a->af) {
	पक्ष AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		प्रत्यागम (0);
	पक्ष AF_INET6:
		प्रति (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		प्रत्यागम (0);
	स्वभाव:
		प्रत्यागम (-1);
	}
}

पूर्णाङ्क
addr_cmp(ध्रुव संरचना xaddr *a, ध्रुव संरचना xaddr *b)
{
	पूर्णाङ्क i;

	यदि (a->af != b->af)
		प्रत्यागम (a->af == AF_INET6 ? 1 : -1);

	विकल्प (a->af) {
	पक्ष AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		यदि (a->v4.s_addr == b->v4.s_addr)
			प्रत्यागम 0;
		प्रत्यागम (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	पक्ष AF_INET6:
		/*
		 * Do this a byte at a time to avoid the above issue and
		 * any endian problems
		 */
		प्रति (i = 0; i < 16; i++)
			यदि (a->addr8[i] - b->addr8[i] != 0)
				प्रत्यागम (a->addr8[i] - b->addr8[i]);
		यदि (a->scope_id == b->scope_id)
			प्रत्यागम (0);
		प्रत्यागम (a->scope_id > b->scope_id ? 1 : -1);
	स्वभाव:
		प्रत्यागम (-1);
	}
}

स्थिर पूर्णाङ्क
addr_is_all0s(ध्रुव संरचना xaddr *a)
{
	पूर्णाङ्क i;

	विकल्प (a->af) {
	पक्ष AF_INET:
		प्रत्यागम (a->v4.s_addr == 0 ? 0 : -1);
	पक्ष AF_INET6:
		प्रति (i = 0; i < 4; i++)
			यदि (a->addr32[i] != 0)
				प्रत्यागम -1;
		प्रत्यागम 0;
	स्वभाव:
		प्रत्यागम -1;
	}
}

/* Increment the specified address. Note, does not do overflow checking */
शून्य
addr_increment(संरचना xaddr *a)
{
	पूर्णाङ्क i;
	uint32_t n;

	विकल्प (a->af) {
	पक्ष AF_INET:
		a->v4.s_addr = htonl(ntohl(a->v4.s_addr) + 1);
		भङ्ग;
	पक्ष AF_INET6:
		प्रति (i = 0; i < 4; i++) {
			/* Increment with carry */
			n = ntohl(a->addr32[3 - i]) + 1;
			a->addr32[3 - i] = htonl(n);
			यदि (n != 0)
				भङ्ग;
		}
		भङ्ग;
	}
}

/*
 * Test whether host portion of address 'a', as determined by 'masklen'
 * is all zeros.
 * Returns 0 if host portion of address is all-zeros,
 * -1 if not all zeros or on failure.
 */
स्थिर पूर्णाङ्क
addr_host_is_all0s(ध्रुव संरचना xaddr *a, u_int masklen)
{
	संरचना xaddr tmp_addr, tmp_आवरणम्, tmp_परिणाम;

	स्मृतिं_प्रतिलिख(&tmp_addr, a, परिमाण(tmp_addr));
	यदि (addr_hostmask(a->af, masklen, &tmp_आवरणम्) == -1)
		प्रत्यागम -1;
	यदि (addr_and(&tmp_परिणाम, &tmp_addr, &tmp_आवरणम्) == -1)
		प्रत्यागम -1;
	प्रत्यागम addr_is_all0s(&tmp_परिणाम);
}

#यदि 0
स्थिर पूर्णाङ्क
addr_host_गन्तव्यम्_all0s(संरचना xaddr *a, u_int masklen)
{
	संरचना xaddr tmp_आवरणम्;

	यदि (addr_netmask(a->af, masklen, &tmp_आवरणम्) == -1)
		प्रत्यागम (-1);
	यदि (addr_and(a, a, &tmp_आवरणम्) == -1)
		प्रत्यागम (-1);
	प्रत्यागम (0);
}
#यदि_अन्तः

पूर्णाङ्क
addr_host_गन्तव्यम्_all1s(संरचना xaddr *a, u_int masklen)
{
	संरचना xaddr tmp_आवरणम्;

	यदि (addr_hostmask(a->af, masklen, &tmp_आवरणम्) == -1)
		प्रत्यागम (-1);
	यदि (addr_or(a, a, &tmp_आवरणम्) == -1)
		प्रत्यागम (-1);
	प्रत्यागम (0);
}

/*
 * Parse string address 'p' into 'n'.
 * Returns 0 on success, -1 on failure.
 */
पूर्णाङ्क
addr_pton(ध्रुव वर्ण *p, संरचना xaddr *n)
{
	संरचना addrinfo hints, *ai;

	स्मृतिं_पूरय(&hints, '\0', परिमाण(hints));
	hints.ai_flags = AI_NUMERICHOST;

	यदि (p == रिक्त || getaddrinfo(p, रिक्त, &hints, &ai) != 0)
		प्रत्यागम -1;

	यदि (ai == रिक्त)
		प्रत्यागम -1;

	यदि (ai->ai_addr == रिक्त) {
		freeaddrinfo(ai);
		प्रत्यागम -1;
	}

	यदि (n != रिक्त && addr_sa_गन्तव्यम्_xaddr(ai->ai_addr, ai->ai_addrlen,
	    n) == -1) {
		freeaddrinfo(ai);
		प्रत्यागम -1;
	}

	freeaddrinfo(ai);
	प्रत्यागम 0;
}

#यदि 0
स्थिर पूर्णाङ्क
addr_sa_pton(ध्रुव वर्ण *h, ध्रुव वर्ण *s, संरचना sockaddr *sa, socklen_t slen)
{
	संरचना addrinfo hints, *ai;

	स्मृतिं_पूरय(&hints, '\0', परिमाण(hints));
	hints.ai_flags = AI_NUMERICHOST;

	यदि (h == रिक्त || getaddrinfo(h, s, &hints, &ai) != 0)
		प्रत्यागम -1;

	यदि (ai == रिक्त)
		प्रत्यागम -1;

	यदि (ai->ai_addr == रिक्त) {
		freeaddrinfo(ai);
		प्रत्यागम -1;
	}

	यदि (sa != रिक्त) {
		यदि (slen < ai->ai_addrlen) {
			freeaddrinfo(ai);
			प्रत्यागम -1;
		}
		स्मृतिं_प्रतिलिख(sa, &ai->ai_addr, ai->ai_addrlen);
	}

	freeaddrinfo(ai);
	प्रत्यागम 0;
}
#यदि_अन्तः

पूर्णाङ्क
addr_ntop(ध्रुव संरचना xaddr *n, वर्ण *p, आकार_t len)
{
	संरचना sockaddr_storage ss;
	socklen_t slen = परिमाण(ss);

	यदि (addr_xaddr_गन्तव्यम्_sa(n, _SA(&ss), &slen, 0) == -1)
		प्रत्यागम -1;
	यदि (p == रिक्त || len == 0)
		प्रत्यागम -1;
	यदि (getnameinfo(_SA(&ss), slen, p, len, रिक्त, 0,
	    NI_NUMERICHOST) != 0)
		प्रत्यागम -1;

	प्रत्यागम 0;
}

/*
 * Parse a CIDR address (x.x.x.x/y or xxxx:yyyy::/z).
 * Return -1 on parse error, -2 on inconsistency or 0 on success.
 */
पूर्णाङ्क
addr_pton_cidr(ध्रुव वर्ण *p, संरचना xaddr *n, u_int *l)
{
	संरचना xaddr tmp;
	u_int masklen = 999;
	वर्ण addrbuf[64], *mp;
	ध्रुव वर्ण *errstr;

	/* Don't modify argument */
	यदि (p == रिक्त || strlcpy(addrbuf, p, परिमाण(addrbuf)) >= परिमाण(addrbuf))
		प्रत्यागम -1;

	यदि ((mp = strchr(addrbuf, '/')) != रिक्त) {
		*mp = '\0';
		mp++;
		masklen = (u_int)strtonum(mp, 0, अधिकतम_पूर्णाङ्कः, &errstr);
		यदि (errstr)
			प्रत्यागम -1;
	}

	यदि (addr_pton(addrbuf, &tmp) == -1)
		प्रत्यागम -1;

	यदि (mp == रिक्त)
		masklen = addr_unicast_masklen(tmp.af);
	यदि (masklen_valid(tmp.af, masklen) == -1)
		प्रत्यागम -2;
	यदि (addr_host_is_all0s(&tmp, masklen) != 0)
		प्रत्यागम -2;

	यदि (n != रिक्त)
		स्मृतिं_प्रतिलिख(n, &tmp, परिमाण(*n));
	यदि (l != रिक्त)
		*l = masklen;

	प्रत्यागम 0;
}

पूर्णाङ्क
addr_netmatch(ध्रुव संरचना xaddr *host, ध्रुव संरचना xaddr *net, u_int masklen)
{
	संरचना xaddr tmp_आवरणम्, tmp_परिणाम;

	यदि (host->af != net->af)
		प्रत्यागम -1;

	यदि (addr_netmask(host->af, masklen, &tmp_आवरणम्) == -1)
		प्रत्यागम -1;
	यदि (addr_and(&tmp_परिणाम, host, &tmp_आवरणम्) == -1)
		प्रत्यागम -1;
	प्रत्यागम addr_cmp(&tmp_परिणाम, net);
}
