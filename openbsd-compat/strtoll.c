/* $OpenBSD: strtoll.c,v 1.6 2005/11/10 10:00:17 espie Exp $ */
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

/* OPENBSD ORIGINAL: lib/libc/stdlib/strtoll.c */

#ಅನ್ತರ್ಭಾವ "includes.h"
#ifndef HAVE_STRTOLL

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

/*
 * Convert a string to a long long.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
long long
strtoll(ಧ್ರುವ ವರ್ಣ *nptr, ವರ್ಣ **endptr, ಪೂರ್ಣಾಙ್ಕ base)
{
	ಧ್ರುವ ವರ್ಣ *s;
	long long acc, cutoff;
	ಪೂರ್ಣಾಙ್ಕ c;
	ಪೂರ್ಣಾಙ್ಕ neg, any, cutlim;

	/*
	 * Skip white space and pick up leading +/- sign if any.
	 * If base is 0, allow 0x for hex and 0 for octal, else
	 * assume decimal; if base is already 16, allow 0x.
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

	/*
	 * Compute the cutoff value between legal numbers and illegal
	 * numbers.  That is the largest legal value, divided by the
	 * base.  An input number that is greater than this value, if
	 * followed by a legal input character, is too big.  One that
	 * is equal to this value may be valid or not; the limit
	 * between valid and invalid numbers is then based on the last
	 * digit.  For instance, if the range for long longs is
	 * [-9223372036854775808..9223372036854775807] and the input base
	 * is 10, cutoff will be set to 922337203685477580 and cutlim to
	 * either 7 (neg==0) or 8 (neg==1), meaning that if we have
	 * accumulated a value > 922337203685477580, or equal but the
	 * next digit is > 7 (or 8), the number is too big, and we will
	 * return a range error.
	 *
	 * Set any if any `digits' consumed; make it negative to indicate
	 * overflow.
	 */
	cutoff = neg ? LLONG_MIN : LLONG_MAX;
	cutlim = cutoff % base;
	cutoff /= base;
	ಯದಿ (neg) {
		ಯದಿ (cutlim > 0) {
			cutlim -= base;
			cutoff += 1;
		}
		cutlim = -cutlim;
	}
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
		ಯದಿ (neg) {
			ಯದಿ (acc < cutoff || (acc == cutoff && c > cutlim)) {
				any = -1;
				acc = LLONG_MIN;
				errno = ERANGE;
			} ಅನ್ಯಥಾ {
				any = 1;
				acc *= base;
				acc -= c;
			}
		} ಅನ್ಯಥಾ {
			ಯದಿ (acc > cutoff || (acc == cutoff && c > cutlim)) {
				any = -1;
				acc = LLONG_MAX;
				errno = ERANGE;
			} ಅನ್ಯಥಾ {
				any = 1;
				acc *= base;
				acc += c;
			}
		}
	}
	ಯದಿ (endptr != 0)
		*endptr = (ವರ್ಣ *) (any ? s - 1 : nptr);
	ಪ್ರತ್ಯಾಗಮ (acc);
}
#endif /* HAVE_STRTOLL */
