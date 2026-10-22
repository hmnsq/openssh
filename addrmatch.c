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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "addr.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "log.h"

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
ಪೂರ್ಣಾಙ್ಕ
addr_match_list(ಧ್ರುವ ವರ್ಣ *addr, ಧ್ರುವ ವರ್ಣ *_list)
{
	ವರ್ಣ *list, *cp, *o;
	ಸಂರಚನಾ xaddr try_addr, match_addr;
	u_int masklen, neg;
	ಪೂರ್ಣಾಙ್ಕ ret = 0, r;

	ಯದಿ (addr != ರಿಕ್ತ && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((o = list = strdup(_list)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯಾವತ್ ((cp = strsep(&list, ",")) != ರಿಕ್ತ) {
		neg = *cp == '!';
		ಯದಿ (neg)
			cp++;
		ಯದಿ (*cp == '\0') {
			ret = -2;
			ಭಙ್ಗ;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		ಯದಿ (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			ಭಙ್ಗ;
		} ಅನ್ಯಥಾ ಯದಿ (r == 0) {
			ಯದಿ (addr != ರಿಕ್ತ && addr_netmatch(&try_addr,
			    &match_addr, masklen) == 0) {
 foundit:
				ಯದಿ (neg) {
					ret = -1;
					ಭಙ್ಗ;
				}
				ret = 1;
			}
			ಅನುವರ್ತ;
		} ಅನ್ಯಥಾ {
			/* If CIDR parse failed, try wildcard string match */
			ಯದಿ (addr != ರಿಕ್ತ && match_pattern(addr, cp) == 1)
				ಗಚ್ಛ foundit;
		}
	}
	ಮುಕ್ತ(o);

	ಪ್ರತ್ಯಾಗಮ ret;
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
ಪೂರ್ಣಾಙ್ಕ
addr_match_cidr_list(ಧ್ರುವ ವರ್ಣ *addr, ಧ್ರುವ ವರ್ಣ *_list)
{
	ವರ್ಣ *list, *cp, *o;
	ಸಂರಚನಾ xaddr try_addr, match_addr;
	u_int masklen;
	ಪೂರ್ಣಾಙ್ಕ ret = 0, r;

	ಯದಿ (addr != ರಿಕ್ತ && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((o = list = strdup(_list)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯಾವತ್ ((cp = strsep(&list, ",")) != ರಿಕ್ತ) {
		ಯದಿ (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			ಭಙ್ಗ;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		ಯದಿ (strlen(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			ಭಙ್ಗ;
		}
#define VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		ಯದಿ (strspn(cp, VALID_CIDR_CHARS) != strlen(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		ಯದಿ (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			ಭಙ್ಗ;
		} ಅನ್ಯಥಾ ಯದಿ (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			ಭಙ್ಗ;
		} ಅನ್ಯಥಾ ಯದಿ (r == 0 && addr != ರಿಕ್ತ) {
			ಯದಿ (addr_netmatch(&try_addr, &match_addr,
			    masklen) == 0)
				ret = 1;
			ಅನುವರ್ತ;
		}
	}
	ಮುಕ್ತ(o);

	ಪ್ರತ್ಯಾಗಮ ret;
}
