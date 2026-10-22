/*	$OpenBSD: addrmatch.c,v 1.19 2026/02/14 00:18:34 jsg Exp $ */

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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "addr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

/*
 * Match "addr" against list pattern list "_list", which may contain a
 * mix of CIDR addresses and old-school wildcards.
 *
 * If addr is NULL, then no matching is performed, but _list is parsed
 * and checked for well-formedness.
 *
 * Returns 1 on match found (never returned when addr == NULL).
 * Returns 0 on if no match found, or no errors found when addr == NULL.
 * Returns -1 on negated match found (never returned when addr == NULL).
 * Returns -2 on invalid list entry.
 */
ਪੂਰਨ
addr_ਮੇਲ_list(ਅਚਲ ਅੱਖਰ *addr, ਅਚਲ ਅੱਖਰ *_list)
{
	ਅੱਖਰ *list, *cp, *o;
	ਬਣਤਰ xaddr try_addr, ਮੇਲ_addr;
	u_int masklen, neg;
	ਪੂਰਨ ret = 0, r;

	ਜੇ (addr != ਨਿਰਾ && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		ਵਾਪਸ 0;
	}
	ਜੇ ((o = list = strdup(_list)) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	ਜਦੋਂ ((cp = strsep(&list, ",")) != ਨਿਰਾ) {
		neg = *cp == '!';
		ਜੇ (neg)
			cp++;
		ਜੇ (*cp == '\0') {
			ret = -2;
			ਰੋਕੋ;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &ਮੇਲ_addr, &masklen);
		ਜੇ (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			ਰੋਕੋ;
		} ਨਹੀਂਤਾਂ ਜੇ (r == 0) {
			ਜੇ (addr != ਨਿਰਾ && addr_netmatch(&try_addr,
			    &ਮੇਲ_addr, masklen) == 0) {
 foundit:
				ਜੇ (neg) {
					ret = -1;
					ਰੋਕੋ;
				}
				ret = 1;
			}
			ਜਾਰੀ;
		} ਨਹੀਂਤਾਂ {
			/* If CIDR parse failed, try wildcard string match */
			ਜੇ (addr != ਨਿਰਾ && ਮੇਲ_ਨਮੂਨਾ(addr, cp) == 1)
				ਜਾਓ foundit;
		}
	}
	ਮੁਕਤ(o);

	ਵਾਪਸ ret;
}

/*
 * Match "addr" against list CIDR list "_list". Lexical wildcards and
 * negation are not supported. If "addr" == NULL, will verify structure
 * of "_list".
 *
 * Returns 1 on match found (never returned when addr == NULL).
 * Returns 0 on if no match found, or no errors found when addr == NULL.
 * Returns -1 on error
 */
ਪੂਰਨ
addr_ਮੇਲ_cidr_list(ਅਚਲ ਅੱਖਰ *addr, ਅਚਲ ਅੱਖਰ *_list)
{
	ਅੱਖਰ *list, *cp, *o;
	ਬਣਤਰ xaddr try_addr, ਮੇਲ_addr;
	u_int masklen;
	ਪੂਰਨ ret = 0, r;

	ਜੇ (addr != ਨਿਰਾ && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		ਵਾਪਸ 0;
	}
	ਜੇ ((o = list = strdup(_list)) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	ਜਦੋਂ ((cp = strsep(&list, ",")) != ਨਿਰਾ) {
		ਜੇ (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			ਰੋਕੋ;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		ਜੇ (ਲੜੀ_ਲੰਬਾਈ(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			ਰੋਕੋ;
		}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		ਜੇ (strspn(cp, VALID_CIDR_CHARS) != ਲੜੀ_ਲੰਬਾਈ(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &ਮੇਲ_addr, &masklen);
		ਜੇ (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			ਰੋਕੋ;
		} ਨਹੀਂਤਾਂ ਜੇ (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			ਰੋਕੋ;
		} ਨਹੀਂਤਾਂ ਜੇ (r == 0 && addr != ਨਿਰਾ) {
			ਜੇ (addr_netmatch(&try_addr, &ਮੇਲ_addr,
			    masklen) == 0)
				ret = 1;
			ਜਾਰੀ;
		}
	}
	ਮੁਕਤ(o);

	ਵਾਪਸ ret;
}
