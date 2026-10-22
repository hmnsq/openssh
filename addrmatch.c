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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <netinet/in.h>

#ضمن <string.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <stdarg.h>

#ضمن "addr.h"
#ضمن "match.h"
#ضمن "log.h"

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
صحيح
addr_سمون_list(ثابت حرف *addr, ثابت حرف *_list)
{
	حرف *list, *cp, *o;
	بنية xaddr try_addr, سمون_addr;
	u_int masklen, neg;
	صحيح ret = 0, r;

	إذا (addr != عدم && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		أرجع 0;
	}
	إذا ((o = list = strdup(_list)) == عدم)
		أرجع -1;
	طالما ((cp = strsep(&list, ",")) != عدم) {
		neg = *cp == '!';
		إذا (neg)
			cp++;
		إذا (*cp == '\0') {
			ret = -2;
			اكسر;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &سمون_addr, &masklen);
		إذا (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			اكسر;
		} وإلا إذا (r == 0) {
			إذا (addr != عدم && addr_netmatch(&try_addr,
			    &سمون_addr, masklen) == 0) {
 foundit:
				إذا (neg) {
					ret = -1;
					اكسر;
				}
				ret = 1;
			}
			استمر;
		} وإلا {
			/* If CIDR parse failed, try wildcard string match */
			إذا (addr != عدم && سمون_نمونه(addr, cp) == 1)
				اذهب foundit;
		}
	}
	حرر(o);

	أرجع ret;
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
صحيح
addr_سمون_cidr_list(ثابت حرف *addr, ثابت حرف *_list)
{
	حرف *list, *cp, *o;
	بنية xaddr try_addr, سمون_addr;
	u_int masklen;
	صحيح ret = 0, r;

	إذا (addr != عدم && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		أرجع 0;
	}
	إذا ((o = list = strdup(_list)) == عدم)
		أرجع -1;
	طالما ((cp = strsep(&list, ",")) != عدم) {
		إذا (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			اكسر;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		إذا (مزي_اوږدوالی(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			اكسر;
		}
#تعریف_کړه VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		إذا (strspn(cp, VALID_CIDR_CHARS) != مزي_اوږدوالی(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &سمون_addr, &masklen);
		إذا (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			اكسر;
		} وإلا إذا (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			اكسر;
		} وإلا إذا (r == 0 && addr != عدم) {
			إذا (addr_netmatch(&try_addr, &سمون_addr,
			    masklen) == 0)
				ret = 1;
			استمر;
		}
	}
	حرر(o);

	أرجع ret;
}
