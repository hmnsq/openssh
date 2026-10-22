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

#شامل "includes.h"
#اگر_غیر_تعریف_شدہ HAVE_STRTOLL

#شامل <sys/types.h>

#شامل <ctype.h>
#شامل <errno.h>
#شامل <limits.h>
#شامل <stdlib.h>

/*
 * Convert a string to a long long.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
طویل طویل
strtoll(ثابت حرف *nptr, حرف **endptr, صحیح بنیاد)
{
	ثابت حرف *s;
	طویل طویل acc, cutoff;
	صحیح c;
	صحیح neg, any, cutlim;

	/*
	 * Skip white space and pick up leading +/- sign if any.
	 * If base is 0, allow 0x for hex and 0 for octal, else
	 * assume decimal; if base is already 16, allow 0x.
	 */
	s = nptr;
	کرو {
		c = (غیرعلامتی حرف) *s++;
	} جب (خلا_ہے(c));
	اگر (c == '-') {
		neg = 1;
		c = *s++;
	} ورنہ {
		neg = 0;
		اگر (c == '+')
			c = *s++;
	}
	اگر ((بنیاد == 0 || بنیاد == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		بنیاد = 16;
	}
	اگر (بنیاد == 0)
		بنیاد = c == '0' ? 8 : 10;

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
	cutlim = cutoff % بنیاد;
	cutoff /= بنیاد;
	اگر (neg) {
		اگر (cutlim > 0) {
			cutlim -= بنیاد;
			cutoff += 1;
		}
		cutlim = -cutlim;
	}
	برائے (acc = 0, any = 0;; c = (غیرعلامتی حرف) *s++) {
		اگر (ہندسہ_ہے(c))
			c -= '0';
		ورنہ اگر (حرف_ہے(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		ورنہ
			توڑو;
		اگر (c >= بنیاد)
			توڑو;
		اگر (any < 0)
			جاری;
		اگر (neg) {
			اگر (acc < cutoff || (acc == cutoff && c > cutlim)) {
				any = -1;
				acc = LLONG_MIN;
				errno = ERANGE;
			} ورنہ {
				any = 1;
				acc *= بنیاد;
				acc -= c;
			}
		} ورنہ {
			اگر (acc > cutoff || (acc == cutoff && c > cutlim)) {
				any = -1;
				acc = LLONG_MAX;
				errno = ERANGE;
			} ورنہ {
				any = 1;
				acc *= بنیاد;
				acc += c;
			}
		}
	}
	اگر (endptr != 0)
		*endptr = (حرف *) (any ? s - 1 : nptr);
	واپس (acc);
}
#اگر_ختم /* HAVE_STRTOLL */
