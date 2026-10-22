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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <netinet/in.h>

#شامل <string.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <stdarg.h>

#شامل "addr.h"
#شامل "match.h"
#شامل "log.h"

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
صحیح
addr_match_list(ثابت نویسه *addr, ثابت نویسه *_list)
{
	نویسه *list, *cp, *o;
	ساختار xaddr try_addr, match_addr;
	u_int masklen, neg;
	صحیح ret = 0, r;

	اگر (addr != پوچ && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		بازگشت 0;
	}
	اگر ((o = list = strdup(_list)) == پوچ)
		بازگشت -1;
	وقتی ((cp = strsep(&list, ",")) != پوچ) {
		neg = *cp == '!';
		اگر (neg)
			cp++;
		اگر (*cp == '\0') {
			ret = -2;
			بشکن;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		اگر (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			بشکن;
		} وگرنه اگر (r == 0) {
			اگر (addr != پوچ && addr_netmatch(&try_addr,
			    &match_addr, masklen) == 0) {
 foundit:
				اگر (neg) {
					ret = -1;
					بشکن;
				}
				ret = 1;
			}
			ادامه;
		} وگرنه {
			/* If CIDR parse failed, try wildcard string match */
			اگر (addr != پوچ && match_pattern(addr, cp) == 1)
				برو foundit;
		}
	}
	آزاد(o);

	بازگشت ret;
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
صحیح
addr_match_cidr_list(ثابت نویسه *addr, ثابت نویسه *_list)
{
	نویسه *list, *cp, *o;
	ساختار xaddr try_addr, match_addr;
	u_int masklen;
	صحیح ret = 0, r;

	اگر (addr != پوچ && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		بازگشت 0;
	}
	اگر ((o = list = strdup(_list)) == پوچ)
		بازگشت -1;
	وقتی ((cp = strsep(&list, ",")) != پوچ) {
		اگر (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			بشکن;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		اگر (strlen(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			بشکن;
		}
#define VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		اگر (strspn(cp, VALID_CIDR_CHARS) != strlen(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		اگر (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			بشکن;
		} وگرنه اگر (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			بشکن;
		} وگرنه اگر (r == 0 && addr != پوچ) {
			اگر (addr_netmatch(&try_addr, &match_addr,
			    masklen) == 0)
				ret = 1;
			ادامه;
		}
	}
	آزاد(o);

	بازگشت ret;
}
