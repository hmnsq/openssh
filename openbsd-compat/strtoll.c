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

#அந்தர்பாவ "includes.h"
#ifndef HAVE_STRTOLL

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdlib.h>

/*
 * Convert a string to a long long.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
long long
strtoll(மாறிலி எழுத்து *nptr, எழுத்து **endptr, முழு base)
{
	மாறிலி எழுத்து *s;
	long long acc, cutoff;
	முழு c;
	முழு neg, any, cutlim;

	/*
	 * Skip white space and pick up leading +/- sign if any.
	 * If base is 0, allow 0x for hex and 0 for octal, else
	 * assume decimal; if base is already 16, allow 0x.
	 */
	s = nptr;
	செய் {
		c = (unsigned எழுத்து) *s++;
	} போது (isspace(c));
	எனில் (c == '-') {
		neg = 1;
		c = *s++;
	} இல்லையெனில் {
		neg = 0;
		எனில் (c == '+')
			c = *s++;
	}
	எனில் ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	எனில் (base == 0)
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
	எனில் (neg) {
		எனில் (cutlim > 0) {
			cutlim -= base;
			cutoff += 1;
		}
		cutlim = -cutlim;
	}
	க்கு (acc = 0, any = 0;; c = (unsigned எழுத்து) *s++) {
		எனில் (isdigit(c))
			c -= '0';
		இல்லையெனில் எனில் (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		இல்லையெனில்
			நிறுத்து;
		எனில் (c >= base)
			நிறுத்து;
		எனில் (any < 0)
			தொடர்;
		எனில் (neg) {
			எனில் (acc < cutoff || (acc == cutoff && c > cutlim)) {
				any = -1;
				acc = LLONG_MIN;
				errno = ERANGE;
			} இல்லையெனில் {
				any = 1;
				acc *= base;
				acc -= c;
			}
		} இல்லையெனில் {
			எனில் (acc > cutoff || (acc == cutoff && c > cutlim)) {
				any = -1;
				acc = LLONG_MAX;
				errno = ERANGE;
			} இல்லையெனில் {
				any = 1;
				acc *= base;
				acc += c;
			}
		}
	}
	எனில் (endptr != 0)
		*endptr = (எழுத்து *) (any ? s - 1 : nptr);
	திரும்பு (acc);
}
#endif /* HAVE_STRTOLL */
