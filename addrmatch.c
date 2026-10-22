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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <netinet/in.h>

#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "addr.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "log.h"

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
முழு
addr_match_list(மாறிலி எழுத்து *addr, மாறிலி எழுத்து *_list)
{
	எழுத்து *list, *cp, *o;
	கட்டமைப்பு xaddr try_addr, match_addr;
	u_int masklen, neg;
	முழு ret = 0, r;

	எனில் (addr != வெற்று && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		திரும்பு 0;
	}
	எனில் ((o = list = strdup(_list)) == வெற்று)
		திரும்பு -1;
	போது ((cp = strsep(&list, ",")) != வெற்று) {
		neg = *cp == '!';
		எனில் (neg)
			cp++;
		எனில் (*cp == '\0') {
			ret = -2;
			நிறுத்து;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		எனில் (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			நிறுத்து;
		} இல்லையெனில் எனில் (r == 0) {
			எனில் (addr != வெற்று && addr_netmatch(&try_addr,
			    &match_addr, masklen) == 0) {
 foundit:
				எனில் (neg) {
					ret = -1;
					நிறுத்து;
				}
				ret = 1;
			}
			தொடர்;
		} இல்லையெனில் {
			/* If CIDR parse failed, try wildcard string match */
			எனில் (addr != வெற்று && match_pattern(addr, cp) == 1)
				செல் foundit;
		}
	}
	விடுவி(o);

	திரும்பு ret;
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
முழு
addr_match_cidr_list(மாறிலி எழுத்து *addr, மாறிலி எழுத்து *_list)
{
	எழுத்து *list, *cp, *o;
	கட்டமைப்பு xaddr try_addr, match_addr;
	u_int masklen;
	முழு ret = 0, r;

	எனில் (addr != வெற்று && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		திரும்பு 0;
	}
	எனில் ((o = list = strdup(_list)) == வெற்று)
		திரும்பு -1;
	போது ((cp = strsep(&list, ",")) != வெற்று) {
		எனில் (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			நிறுத்து;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		எனில் (strlen(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			நிறுத்து;
		}
#define VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		எனில் (strspn(cp, VALID_CIDR_CHARS) != strlen(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		எனில் (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			நிறுத்து;
		} இல்லையெனில் எனில் (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			நிறுத்து;
		} இல்லையெனில் எனில் (r == 0 && addr != வெற்று) {
			எனில் (addr_netmatch(&try_addr, &match_addr,
			    masklen) == 0)
				ret = 1;
			தொடர்;
		}
	}
	விடுவி(o);

	திரும்பு ret;
}
