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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ifndef HAVE_STRTOULL

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

/*
 * Convert a string to an unsigned long long.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
unsigned long long
strtoull(ಧ್ರುವ ವರ್ಣ *nptr, ವರ್ಣ **endptr, ಪೂರ್ಣಾಙ್ಕ base)
{
	ಧ್ರುವ ವರ್ಣ *s;
	unsigned long long acc, cutoff;
	ಪೂರ್ಣಾಙ್ಕ c;
	ಪೂರ್ಣಾಙ್ಕ neg, any, cutlim;

	/*
	 * See strtoq for comments as to the logic used.
	 */
	s = nptr;
	ಕುರು {
		c = (unsigned ವರ್ಣ) *s++;
	} ಯಾವತ್ (isspace(c));
	ಯದಿ (c == '-') {
		neg = 1;
		c = *s++;
	} ಅನ್ಯಥಾ { 
		neg = 0;
		ಯದಿ (c == '+')
			c = *s++;
	}
	ಯದಿ ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	ಯದಿ (base == 0)
		base = c == '0' ? 8 : 10;

	cutoff = ULLONG_MAX / (unsigned long long)base;
	cutlim = ULLONG_MAX % (unsigned long long)base;
	ಪ್ರತಿ (acc = 0, any = 0;; c = (unsigned ವರ್ಣ) *s++) {
		ಯದಿ (isdigit(c))
			c -= '0';
		ಅನ್ಯಥಾ ಯದಿ (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		ಅನ್ಯಥಾ
			ಭಙ್ಗ;
		ಯದಿ (c >= base)
			ಭಙ್ಗ;
		ಯದಿ (any < 0)
			ಅನುವರ್ತ;
		ಯದಿ (acc > cutoff || (acc == cutoff && c > cutlim)) {
			any = -1;
			acc = ULLONG_MAX;
			errno = ERANGE;
		} ಅನ್ಯಥಾ {
			any = 1;
			acc *= (unsigned long long)base;
			acc += c;
		}
	}
	ಯದಿ (neg && any > 0)
		acc = -acc;
	ಯದಿ (endptr != 0)
		*endptr = (ವರ್ಣ *) (any ? s - 1 : nptr);
	ಪ್ರತ್ಯಾಗಮ (acc);
}
#endif /* !HAVE_STRTOULL */
