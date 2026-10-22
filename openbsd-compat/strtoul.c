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

#অন্তর্ভাব "includes.h"
#ifndef HAVE_STRTOUL

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdlib.h>

/*
 * Convert a string to an unsigned long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
unsigned long
strtoul(ধ্রুবক অক্ষর *nptr, অক্ষর **endptr, পূর্ণসংখ্যা base)
{
	ধ্রুবক অক্ষর *s;
	unsigned long acc, cutoff;
	পূর্ণসংখ্যা c;
	পূর্ণসংখ্যা neg, any, cutlim;

	/*
	 * See strtol for comments as to the logic used.
	 */
	s = nptr;
	করো {
		c = (unsigned অক্ষর) *s++;
	} যখন (isspace(c));
	যদি (c == '-') {
		neg = 1;
		c = *s++;
	} অন্যথা {
		neg = 0;
		যদি (c == '+')
			c = *s++;
	}
	যদি ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	যদি (base == 0)
		base = c == '0' ? 8 : 10;

	cutoff = ULONG_MAX / (unsigned long)base;
	cutlim = ULONG_MAX % (unsigned long)base;
	জন্য (acc = 0, any = 0;; c = (unsigned অক্ষর) *s++) {
		যদি (isdigit(c))
			c -= '0';
		অন্যথা যদি (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		অন্যথা
			বিরতি;
		যদি (c >= base)
			বিরতি;
		যদি (any < 0)
			চালু;
		যদি (acc > cutoff || acc == cutoff && c > cutlim) {
			any = -1;
			acc = ULONG_MAX;
			errno = ERANGE;
		} অন্যথা {
			any = 1;
			acc *= (unsigned long)base;
			acc += c;
		}
	}
	যদি (neg && any > 0)
		acc = -acc;
	যদি (endptr != 0)
		*endptr = (অক্ষর *) (any ? s - 1 : nptr);
	ফেরত (acc);
}
#endif /* !HAVE_STRTOUL */
