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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <netinet/in.h>

#समावेश <string.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <stdarg.h>

#समावेश "addr.h"
#समावेश "match.h"
#समावेश "log.h"

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
पूर्णांक
addr_match_list(स्थिर अक्षर *addr, स्थिर अक्षर *_list)
{
	अक्षर *list, *cp, *o;
	काष्ठा xaddr try_addr, match_addr;
	u_int masklen, neg;
	पूर्णांक ret = 0, r;

	अगर (addr != शून्य && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		वापस 0;
	}
	अगर ((o = list = strdup(_list)) == शून्य)
		वापस -1;
	जबतक ((cp = strsep(&list, ",")) != शून्य) {
		neg = *cp == '!';
		अगर (neg)
			cp++;
		अगर (*cp == '\0') {
			ret = -2;
			अवरोध;
		}
		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		अगर (r == -2) {
			debug2_f("inconsistent mask length for "
			    "match network \"%.100s\"", cp);
			ret = -2;
			अवरोध;
		} अन्यथा अगर (r == 0) {
			अगर (addr != शून्य && addr_netmatch(&try_addr,
			    &match_addr, masklen) == 0) {
 foundit:
				अगर (neg) {
					ret = -1;
					अवरोध;
				}
				ret = 1;
			}
			जारी;
		} अन्यथा {
			/* If CIDR parse failed, try wildcard string match */
			अगर (addr != शून्य && match_pattern(addr, cp) == 1)
				जाओ foundit;
		}
	}
	मुक्त(o);

	वापस ret;
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
पूर्णांक
addr_match_cidr_list(स्थिर अक्षर *addr, स्थिर अक्षर *_list)
{
	अक्षर *list, *cp, *o;
	काष्ठा xaddr try_addr, match_addr;
	u_int masklen;
	पूर्णांक ret = 0, r;

	अगर (addr != शून्य && addr_pton(addr, &try_addr) != 0) {
		debug2_f("couldn't parse address %.100s", addr);
		वापस 0;
	}
	अगर ((o = list = strdup(_list)) == शून्य)
		वापस -1;
	जबतक ((cp = strsep(&list, ",")) != शून्य) {
		अगर (*cp == '\0') {
			error_f("empty entry in list \"%.100s\"", o);
			ret = -1;
			अवरोध;
		}

		/*
		 * NB. This function is called in pre-auth with untrusted data,
		 * so be extra paranoid about junk reaching getaddrinfo (via
		 * addr_pton_cidr).
		 */

		/* Stop junk from reaching getaddrinfo. +3 is for masklen */
		अगर (म_माप(cp) > INET6_ADDRSTRLEN + 3) {
			error_f("list entry \"%.100s\" too long", cp);
			ret = -1;
			अवरोध;
		}
#घोषणा VALID_CIDR_CHARS "0123456789abcdefABCDEF.:/"
		अगर (म_अखोज(cp, VALID_CIDR_CHARS) != म_माप(cp)) {
			error_f("list entry \"%.100s\" contains invalid "
			    "characters", cp);
			ret = -1;
		}

		/* Prefer CIDR address matching */
		r = addr_pton_cidr(cp, &match_addr, &masklen);
		अगर (r == -1) {
			error("Invalid network entry \"%.100s\"", cp);
			ret = -1;
			अवरोध;
		} अन्यथा अगर (r == -2) {
			error("Inconsistent mask length for "
			    "network \"%.100s\"", cp);
			ret = -1;
			अवरोध;
		} अन्यथा अगर (r == 0 && addr != शून्य) {
			अगर (addr_netmatch(&try_addr, &match_addr,
			    masklen) == 0)
				ret = 1;
			जारी;
		}
	}
	मुक्त(o);

	वापस ret;
}
