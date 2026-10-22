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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <netinet/in.h>

#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdarg.h>

#অন্তর্ভাৱ "addr.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "log.h"

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
পূর্ণাঙ্ক
addr_match_list(ধ্রুৱ ৱর্ণ *addr, ধ্রুৱ ৱর্ণ *_list)
{
	ৱর্ণ *list, *cp, *o;
	সংরচনা xaddr try_addr, match_addr;
	u_int masklen, neg;
	পূর্ণাঙ্ক ret = 0, r;

	যদি (addr != রিক্ত && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		ঘূৰাই 0;
	}
	যদি ((o = list = strdup(_list)) == রিক্ত)
		ঘূৰাই -1;
	যেতিয়ালৈ ((cp = strsep(&list, ",")) != রিক্ত) {
		neg = *cp == '!';
		যদি (neg)
			cp++;
		যদি (*cp == '\0') {
			ret = -2;
			ভঙ্গ;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		যদি (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			ভঙ্গ;
		} অন্যথা যদি (r == 0) {
			যদি (addr != রিক্ত && addr_netmatch(&try_addr,
			    &match_addr, masklen) == 0) {
 foundit:
				যদি (neg) {
					ret = -1;
					ভঙ্গ;
				}
				ret = 1;
			}
			অনুৱর্ত;
		} অন্যথা {
			/* If CIDR parse failed, try wildcard string match */
			যদি (addr != রিক্ত && match_pattern(addr, cp) == 1)
				গচ্ছ foundit;
		}
	}
	মুক্ত(o);

	ঘূৰাই ret;
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
পূর্ণাঙ্ক
addr_match_cidr_list(ধ্রুৱ ৱর্ণ *addr, ধ্রুৱ ৱর্ণ *_list)
{
	ৱর্ণ *list, *cp, *o;
	সংরচনা xaddr try_addr, match_addr;
	u_int masklen;
	পূর্ণাঙ্ক ret = 0, r;

	যদি (addr != রিক্ত && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		ঘূৰাই 0;
	}
	যদি ((o = list = strdup(_list)) == রিক্ত)
		ঘূৰাই -1;
	যেতিয়ালৈ ((cp = strsep(&list, ",")) != রিক্ত) {
		যদি (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			ভঙ্গ;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		যদি (strlen(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			ভঙ্গ;
		}
#define VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		যদি (strspn(cp, VALID_CIDR_CHARS) != strlen(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		যদি (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			ভঙ্গ;
		} অন্যথা যদি (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			ভঙ্গ;
		} অন্যথা যদি (r == 0 && addr != রিক্ত) {
			যদি (addr_netmatch(&try_addr, &match_addr,
			    masklen) == 0)
				ret = 1;
			অনুৱর্ত;
		}
	}
	মুক্ত(o);

	ঘূৰাই ret;
}
