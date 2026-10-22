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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <netinet/in.h>

#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "addr.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "log.h"

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
પૂર્ણાંક
addr_match_list(અચલ અક્ષર *addr, અચલ અક્ષર *_list)
{
	અક્ષર *list, *cp, *o;
	સંરચના xaddr try_addr, match_addr;
	u_int masklen, neg;
	પૂર્ણાંક ret = 0, r;

	જો (addr != ખાલી && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		પાછા 0;
	}
	જો ((o = list = strdup(_list)) == ખાલી)
		પાછા -1;
	જ્યારે ((cp = strsep(&list, ",")) != ખાલી) {
		neg = *cp == '!';
		જો (neg)
			cp++;
		જો (*cp == '\0') {
			ret = -2;
			તોડો;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		જો (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			તોડો;
		} નહીંતર જો (r == 0) {
			જો (addr != ખાલી && addr_netmatch(&try_addr,
			    &match_addr, masklen) == 0) {
 foundit:
				જો (neg) {
					ret = -1;
					તોડો;
				}
				ret = 1;
			}
			ચાલુ;
		} નહીંતર {
			/* If CIDR parse failed, try wildcard string match */
			જો (addr != ખાલી && match_pattern(addr, cp) == 1)
				જાઓ foundit;
		}
	}
	મુક્ત(o);

	પાછા ret;
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
પૂર્ણાંક
addr_match_cidr_list(અચલ અક્ષર *addr, અચલ અક્ષર *_list)
{
	અક્ષર *list, *cp, *o;
	સંરચના xaddr try_addr, match_addr;
	u_int masklen;
	પૂર્ણાંક ret = 0, r;

	જો (addr != ખાલી && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		પાછા 0;
	}
	જો ((o = list = strdup(_list)) == ખાલી)
		પાછા -1;
	જ્યારે ((cp = strsep(&list, ",")) != ખાલી) {
		જો (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			તોડો;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		જો (strlen(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			તોડો;
		}
#define VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		જો (strspn(cp, VALID_CIDR_CHARS) != strlen(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		જો (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			તોડો;
		} નહીંતર જો (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			તોડો;
		} નહીંતર જો (r == 0 && addr != ખાલી) {
			જો (addr_netmatch(&try_addr, &match_addr,
			    masklen) == 0)
				ret = 1;
			ચાલુ;
		}
	}
	મુક્ત(o);

	પાછા ret;
}
