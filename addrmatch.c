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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <netinet/in.h>

#అన్తర్భావ <string.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "addr.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "log.h"

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
పూర్ణాంకం
addr_సరిపోలిక_list(స్థిరరాశి అక్షరం *addr, స్థిరరాశి అక్షరం *_list)
{
	అక్షరం *list, *cp, *o;
	నిర్మాణం xaddr try_addr, సరిపోలిక_addr;
	u_int masklen, neg;
	పూర్ణాంకం ret = 0, r;

	ఒకవేళ (addr != ఖాళీ && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		తిరిగి 0;
	}
	ఒకవేళ ((o = list = strdup(_list)) == ఖాళీ)
		తిరిగి -1;
	అయితే ((cp = strsep(&list, ",")) != ఖాళీ) {
		neg = *cp == '!';
		ఒకవేళ (neg)
			cp++;
		ఒకవేళ (*cp == '\0') {
			ret = -2;
			ఆపు;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &సరిపోలిక_addr, &masklen);
		ఒకవేళ (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			ఆపు;
		} లేకపోతే ఒకవేళ (r == 0) {
			ఒకవేళ (addr != ఖాళీ && addr_netmatch(&try_addr,
			    &సరిపోలిక_addr, masklen) == 0) {
 foundit:
				ఒకవేళ (neg) {
					ret = -1;
					ఆపు;
				}
				ret = 1;
			}
			కొనసాగు;
		} లేకపోతే {
			/* If CIDR parse failed, try wildcard string match */
			ఒకవేళ (addr != ఖాళీ && సరిపోలిక_నమూనా(addr, cp) == 1)
				వెళ్ళు foundit;
		}
	}
	విడుదల(o);

	తిరిగి ret;
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
పూర్ణాంకం
addr_సరిపోలిక_cidr_list(స్థిరరాశి అక్షరం *addr, స్థిరరాశి అక్షరం *_list)
{
	అక్షరం *list, *cp, *o;
	నిర్మాణం xaddr try_addr, సరిపోలిక_addr;
	u_int masklen;
	పూర్ణాంకం ret = 0, r;

	ఒకవేళ (addr != ఖాళీ && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		తిరిగి 0;
	}
	ఒకవేళ ((o = list = strdup(_list)) == ఖాళీ)
		తిరిగి -1;
	అయితే ((cp = strsep(&list, ",")) != ఖాళీ) {
		ఒకవేళ (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			ఆపు;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		ఒకవేళ (అక్షరశ్రేణి_పొడవు(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			ఆపు;
		}
#నిర్వచించు VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		ఒకవేళ (strspn(cp, VALID_CIDR_CHARS) != అక్షరశ్రేణి_పొడవు(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &సరిపోలిక_addr, &masklen);
		ఒకవేళ (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			ఆపు;
		} లేకపోతే ఒకవేళ (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			ఆపు;
		} లేకపోతే ఒకవేళ (r == 0 && addr != ఖాళీ) {
			ఒకవేళ (addr_netmatch(&try_addr, &సరిపోలిక_addr,
			    masklen) == 0)
				ret = 1;
			కొనసాగు;
		}
	}
	విడుదల(o);

	తిరిగి ret;
}
