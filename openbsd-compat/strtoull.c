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

#அந்தர்பாவ "includes.h"
#ifndef HAVE_STRTOULL

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdlib.h>

/*
 * Convert a string to an unsigned long long.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
unsigned long long
strtoull(மாறிலி எழுத்து *nptr, எழுத்து **endptr, முழு base)
{
	மாறிலி எழுத்து *s;
	unsigned long long acc, cutoff;
	முழு c;
	முழு neg, any, cutlim;

	/*
	 * See strtoq for comments as to the logic used.
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

	cutoff = ULLONG_MAX / (unsigned long long)base;
	cutlim = ULLONG_MAX % (unsigned long long)base;
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
		எனில் (acc > cutoff || (acc == cutoff && c > cutlim)) {
			any = -1;
			acc = ULLONG_MAX;
			errno = ERANGE;
		} இல்லையெனில் {
			any = 1;
			acc *= (unsigned long long)base;
			acc += c;
		}
	}
	எனில் (neg && any > 0)
		acc = -acc;
	எனில் (endptr != 0)
		*endptr = (எழுத்து *) (any ? s - 1 : nptr);
	திரும்பு (acc);
}
#endif /* !HAVE_STRTOULL */
