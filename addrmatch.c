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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <netinet/in.h>

#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "addr.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "log.h"

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
पूर्णाङ्क
addr_मेलनम्_list(ध्रुव वर्ण *addr, ध्रुव वर्ण *_list)
{
	वर्ण *list, *cp, *o;
	संरचना xaddr try_addr, मेलनम्_addr;
	u_int masklen, neg;
	पूर्णाङ्क ret = 0, r;

	यदि (addr != रिक्त && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		प्रत्यागम 0;
	}
	यदि ((o = list = strdup(_list)) == रिक्त)
		प्रत्यागम -1;
	यावत् ((cp = strsep(&list, ",")) != रिक्त) {
		neg = *cp == '!';
		यदि (neg)
			cp++;
		यदि (*cp == '\0') {
			ret = -2;
			भङ्ग;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &मेलनम्_addr, &masklen);
		यदि (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			भङ्ग;
		} अन्यथा यदि (r == 0) {
			यदि (addr != रिक्त && addr_netmatch(&try_addr,
			    &मेलनम्_addr, masklen) == 0) {
 foundit:
				यदि (neg) {
					ret = -1;
					भङ्ग;
				}
				ret = 1;
			}
			अनुवर्त;
		} अन्यथा {
			/* If CIDR parse failed, try wildcard string match */
			यदि (addr != रिक्त && मेलनम्_आदर्शः(addr, cp) == 1)
				गच्छ foundit;
		}
	}
	मुक्त(o);

	प्रत्यागम ret;
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
पूर्णाङ्क
addr_मेलनम्_cidr_list(ध्रुव वर्ण *addr, ध्रुव वर्ण *_list)
{
	वर्ण *list, *cp, *o;
	संरचना xaddr try_addr, मेलनम्_addr;
	u_int masklen;
	पूर्णाङ्क ret = 0, r;

	यदि (addr != रिक्त && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		प्रत्यागम 0;
	}
	यदि ((o = list = strdup(_list)) == रिक्त)
		प्रत्यागम -1;
	यावत् ((cp = strsep(&list, ",")) != रिक्त) {
		यदि (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			भङ्ग;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		यदि (वाक्यदैर्घ्यम्(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			भङ्ग;
		}
#परिभाषय VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		यदि (strspn(cp, VALID_CIDR_CHARS) != वाक्यदैर्घ्यम्(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &मेलनम्_addr, &masklen);
		यदि (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			भङ्ग;
		} अन्यथा यदि (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			भङ्ग;
		} अन्यथा यदि (r == 0 && addr != रिक्त) {
			यदि (addr_netmatch(&try_addr, &मेलनम्_addr,
			    masklen) == 0)
				ret = 1;
			अनुवर्त;
		}
	}
	मुक्त(o);

	प्रत्यागम ret;
}
