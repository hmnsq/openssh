/*	$OpenBSD: strtoull.c,v 1.5 2005/08/08 08:05:37 espie Exp $ */
/*-
 * Copyright (c) 1992 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/stdlib/strtoull.c */

#include "includes.h"
#ifndef HAVE_STRTOULL

#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

/*
 * Convert a string to an unsigned long long.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
unsigned long long
strtoull(const char *nptr, char **endptr, 정수 base)
{
	const char *s;
	unsigned long long acc, cutoff;
	정수 c;
	정수 neg, any, cutlim;

	/*
	 * See strtoq for comments as to the logic used.
	 */
	s = nptr;
	do {
		c = (unsigned char) *s++;
	} 동안 (isspace(c));
	만약 (c == '-') {
		neg = 1;
		c = *s++;
	} 아니면 { 
		neg = 0;
		만약 (c == '+')
			c = *s++;
	}
	만약 ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	만약 (base == 0)
		base = c == '0' ? 8 : 10;

	cutoff = ULLONG_MAX / (unsigned long long)base;
	cutlim = ULLONG_MAX % (unsigned long long)base;
	위해 (acc = 0, any = 0;; c = (unsigned char) *s++) {
		만약 (isdigit(c))
			c -= '0';
		아니면 만약 (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		아니면
			break;
		만약 (c >= base)
			break;
		만약 (any < 0)
			continue;
		만약 (acc > cutoff || (acc == cutoff && c > cutlim)) {
			any = -1;
			acc = ULLONG_MAX;
			errno = ERANGE;
		} 아니면 {
			any = 1;
			acc *= (unsigned long long)base;
			acc += c;
		}
	}
	만약 (neg && any > 0)
		acc = -acc;
	만약 (endptr != 0)
		*endptr = (char *) (any ? s - 1 : nptr);
	반환 (acc);
}
#endif /* !HAVE_STRTOULL */
