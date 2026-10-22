/*	$OpenBSD: strtoul.c,v 1.7 2005/08/08 08:05:37 espie Exp $ */
/*
 * Copyright (c) 1990 Regents of the University of California.
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

/* OPENBSD ORIGINAL: lib/libc/stdlib/strtoul.c */

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ifndef HAVE_STRTOUL

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

/*
 * Convert a string to an unsigned long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
unsigned long
strtoul(ଅଚଳ ଅକ୍ଷର *nptr, ଅକ୍ଷର **endptr, ପୂର୍ଣ୍ଣସଂଖ୍ୟା base)
{
	ଅଚଳ ଅକ୍ଷର *s;
	unsigned long acc, cutoff;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା neg, any, cutlim;

	/*
	 * See strtol for comments as to the logic used.
	 */
	s = nptr;
	କର {
		c = (unsigned ଅକ୍ଷର) *s++;
	} ଯେତେବେଳେ (isspace(c));
	ଯଦି (c == '-') {
		neg = 1;
		c = *s++;
	} ଅନ୍ୟଥା {
		neg = 0;
		ଯଦି (c == '+')
			c = *s++;
	}
	ଯଦି ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	ଯଦି (base == 0)
		base = c == '0' ? 8 : 10;

	cutoff = ULONG_MAX / (unsigned long)base;
	cutlim = ULONG_MAX % (unsigned long)base;
	ପାଇଁ (acc = 0, any = 0;; c = (unsigned ଅକ୍ଷର) *s++) {
		ଯଦି (isdigit(c))
			c -= '0';
		ଅନ୍ୟଥା ଯଦି (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
		ଯଦି (c >= base)
			ଭାଙ୍ଗ;
		ଯଦି (any < 0)
			ଜାରି;
		ଯଦି (acc > cutoff || acc == cutoff && c > cutlim) {
			any = -1;
			acc = ULONG_MAX;
			errno = ERANGE;
		} ଅନ୍ୟଥା {
			any = 1;
			acc *= (unsigned long)base;
			acc += c;
		}
	}
	ଯଦି (neg && any > 0)
		acc = -acc;
	ଯଦି (endptr != 0)
		*endptr = (ଅକ୍ଷର *) (any ? s - 1 : nptr);
	ଫେରନ୍ତୁ (acc);
}
#endif /* !HAVE_STRTOUL */
