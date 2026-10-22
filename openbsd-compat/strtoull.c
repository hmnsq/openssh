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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_STRTOULL

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

/*
 * Convert a string to an unsigned long long.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ
strtoull(ਅਚਲ ਅੱਖਰ *nptr, ਅੱਖਰ **endptr, ਪੂਰਨ ਅਧਾਰ)
{
	ਅਚਲ ਅੱਖਰ *s;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ acc, cutoff;
	ਪੂਰਨ c;
	ਪੂਰਨ neg, any, cutlim;

	/*
	 * See strtoq for comments as to the logic used.
	 */
	s = nptr;
	ਕਰੋ {
		c = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ) *s++;
	} ਜਦੋਂ (ਖਾਲੀ_ਥਾਂ_ਹੈ(c));
	ਜੇ (c == '-') {
		neg = 1;
		c = *s++;
	} ਨਹੀਂਤਾਂ { 
		neg = 0;
		ਜੇ (c == '+')
			c = *s++;
	}
	ਜੇ ((ਅਧਾਰ == 0 || ਅਧਾਰ == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		ਅਧਾਰ = 16;
	}
	ਜੇ (ਅਧਾਰ == 0)
		ਅਧਾਰ = c == '0' ? 8 : 10;

	cutoff = ULLONG_MAX / (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਅਧਾਰ;
	cutlim = ULLONG_MAX % (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਅਧਾਰ;
	ਲਈ (acc = 0, any = 0;; c = (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ) *s++) {
		ਜੇ (ਅੰਕ_ਹੈ(c))
			c -= '0';
		ਨਹੀਂਤਾਂ ਜੇ (ਅੱਖਰ_ਹੈ(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
		ਜੇ (c >= ਅਧਾਰ)
			ਰੋਕੋ;
		ਜੇ (any < 0)
			ਜਾਰੀ;
		ਜੇ (acc > cutoff || (acc == cutoff && c > cutlim)) {
			any = -1;
			acc = ULLONG_MAX;
			errno = ERANGE;
		} ਨਹੀਂਤਾਂ {
			any = 1;
			acc *= (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਅਧਾਰ;
			acc += c;
		}
	}
	ਜੇ (neg && any > 0)
		acc = -acc;
	ਜੇ (endptr != 0)
		*endptr = (ਅੱਖਰ *) (any ? s - 1 : nptr);
	ਵਾਪਸ (acc);
}
#ਜੇ_ਅੰਤ /* !HAVE_STRTOULL */
