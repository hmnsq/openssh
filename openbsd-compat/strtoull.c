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
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRTOULL

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
ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ
strtoull(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *nptr, ಅಕ್ಷರ **endptr, ಪೂರ್ಣಾಂಕ ತಳ)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ acc, cutoff;
	ಪೂರ್ಣಾಂಕ c;
	ಪೂರ್ಣಾಂಕ neg, any, cutlim;

	/*
	 * See strtoq for comments as to the logic used.
	 */
	s = nptr;
	ಮಾಡು {
		c = (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ) *s++;
	} ಆಗ (ಖಾಲಿಯೇ(c));
	ಆದರೆ (c == '-') {
		neg = 1;
		c = *s++;
	} ಇಲ್ಲದಿದ್ದರೆ { 
		neg = 0;
		ಆದರೆ (c == '+')
			c = *s++;
	}
	ಆದರೆ ((ತಳ == 0 || ತಳ == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		ತಳ = 16;
	}
	ಆದರೆ (ತಳ == 0)
		ತಳ = c == '0' ? 8 : 10;

	cutoff = ULLONG_MAX / (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ತಳ;
	cutlim = ULLONG_MAX % (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ತಳ;
	ಗಾಗಿ (acc = 0, any = 0;; c = (ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ) *s++) {
		ಆದರೆ (ಅಂಕಿಯೇ(c))
			c -= '0';
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರವೇ(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (c >= ತಳ)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (any < 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (acc > cutoff || (acc == cutoff && c > cutlim)) {
			any = -1;
			acc = ULLONG_MAX;
			errno = ERANGE;
		} ಇಲ್ಲದಿದ್ದರೆ {
			any = 1;
			acc *= (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ತಳ;
			acc += c;
		}
	}
	ಆದರೆ (neg && any > 0)
		acc = -acc;
	ಆದರೆ (endptr != 0)
		*endptr = (ಅಕ್ಷರ *) (any ? s - 1 : nptr);
	ಹಿಂತಿರುಗಿ (acc);
}
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_STRTOULL */
