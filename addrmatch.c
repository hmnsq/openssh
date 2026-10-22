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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <netinet/in.h>

#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "addr.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "log.h"

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
പൂർണ്ണസംഖ്യ
addr_match_list(സ്ഥിരം അക്ഷരം *addr, സ്ഥിരം അക്ഷരം *_list)
{
	അക്ഷരം *list, *cp, *o;
	ഘടന xaddr try_addr, match_addr;
	u_int masklen, neg;
	പൂർണ്ണസംഖ്യ ret = 0, r;

	എങ്കിൽ (addr != ശൂന്യ && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		തിരികെ 0;
	}
	എങ്കിൽ ((o = list = strdup(_list)) == ശൂന്യ)
		തിരികെ -1;
	ആകുമ്പോൾ ((cp = strsep(&list, ",")) != ശൂന്യ) {
		neg = *cp == '!';
		എങ്കിൽ (neg)
			cp++;
		എങ്കിൽ (*cp == '\0') {
			ret = -2;
			നിർത്തുക;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		എങ്കിൽ (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			നിർത്തുക;
		} അല്ലെങ്കിൽ എങ്കിൽ (r == 0) {
			എങ്കിൽ (addr != ശൂന്യ && addr_netmatch(&try_addr,
			    &match_addr, masklen) == 0) {
 foundit:
				എങ്കിൽ (neg) {
					ret = -1;
					നിർത്തുക;
				}
				ret = 1;
			}
			തുടരുക;
		} അല്ലെങ്കിൽ {
			/* If CIDR parse failed, try wildcard string match */
			എങ്കിൽ (addr != ശൂന്യ && match_pattern(addr, cp) == 1)
				പോകുക foundit;
		}
	}
	സ്വതന്ത്രം(o);

	തിരികെ ret;
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
പൂർണ്ണസംഖ്യ
addr_match_cidr_list(സ്ഥിരം അക്ഷരം *addr, സ്ഥിരം അക്ഷരം *_list)
{
	അക്ഷരം *list, *cp, *o;
	ഘടന xaddr try_addr, match_addr;
	u_int masklen;
	പൂർണ്ണസംഖ്യ ret = 0, r;

	എങ്കിൽ (addr != ശൂന്യ && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		തിരികെ 0;
	}
	എങ്കിൽ ((o = list = strdup(_list)) == ശൂന്യ)
		തിരികെ -1;
	ആകുമ്പോൾ ((cp = strsep(&list, ",")) != ശൂന്യ) {
		എങ്കിൽ (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			നിർത്തുക;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		എങ്കിൽ (strlen(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			നിർത്തുക;
		}
#define VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		എങ്കിൽ (strspn(cp, VALID_CIDR_CHARS) != strlen(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		എങ്കിൽ (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			നിർത്തുക;
		} അല്ലെങ്കിൽ എങ്കിൽ (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			നിർത്തുക;
		} അല്ലെങ്കിൽ എങ്കിൽ (r == 0 && addr != ശൂന്യ) {
			എങ്കിൽ (addr_netmatch(&try_addr, &match_addr,
			    masklen) == 0)
				ret = 1;
			തുടരുക;
		}
	}
	സ്വതന്ത്രം(o);

	തിരികെ ret;
}
