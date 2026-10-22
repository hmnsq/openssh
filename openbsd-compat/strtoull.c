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
strtoull(const var_na *nptr, var_na **endptr, ចំនួនគត់ base)
{
	const var_na *s;
	unsigned long long acc, cutoff;
	ចំនួនគត់ c;
	ចំនួនគត់ neg, any, cutlim;

	/*
	 * See strtoq for comments as to the logic used.
	 */
	s = nptr;
	do {
		c = (unsigned var_na) *s++;
	} ខណៈពេល (isspace(c));
	ប្រសិនបើ (c == '-') {
		neg = 1;
		c = *s++;
	} បើមិនដូច្នេះ { 
		neg = 0;
		ប្រសិនបើ (c == '+')
			c = *s++;
	}
	ប្រសិនបើ ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	ប្រសិនបើ (base == 0)
		base = c == '0' ? 8 : 10;

	cutoff = ULLONG_MAX / (unsigned long long)base;
	cutlim = ULLONG_MAX % (unsigned long long)base;
	សម្រាប់ (acc = 0, any = 0;; c = (unsigned var_na) *s++) {
		ប្រសិនបើ (isdigit(c))
			c -= '0';
		បើមិនដូច្នេះ ប្រសិនបើ (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		បើមិនដូច្នេះ
			bha_nga;
		ប្រសិនបើ (c >= base)
			bha_nga;
		ប្រសិនបើ (any < 0)
			continue;
		ប្រសិនបើ (acc > cutoff || (acc == cutoff && c > cutlim)) {
			any = -1;
			acc = ULLONG_MAX;
			errno = ERANGE;
		} បើមិនដូច្នេះ {
			any = 1;
			acc *= (unsigned long long)base;
			acc += c;
		}
	}
	ប្រសិនបើ (neg && any > 0)
		acc = -acc;
	ប្រសិនបើ (endptr != 0)
		*endptr = (var_na *) (any ? s - 1 : nptr);
	ត្រឡប់ (acc);
}
#endif /* !HAVE_STRTOULL */
