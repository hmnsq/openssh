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

#ضمن "includes.h"
#جے_بنا_تعریف HAVE_STRTOUL

#ضمن <ctype.h>
#ضمن <errno.h>
#ضمن <limits.h>
#ضمن <stdlib.h>

/*
 * Convert a string to an unsigned long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
بنانشانی لما
strtoul(ثابت حرف *nptr, حرف **endptr, صحيح ادھار)
{
	ثابت حرف *s;
	بنانشانی لما acc, cutoff;
	صحيح c;
	صحيح neg, any, cutlim;

	/*
	 * See strtol for comments as to the logic used.
	 */
	s = nptr;
	افعل {
		c = (بنانشانی حرف) *s++;
	} طالما (خلا_اے(c));
	إذا (c == '-') {
		neg = 1;
		c = *s++;
	} وإلا {
		neg = 0;
		إذا (c == '+')
			c = *s++;
	}
	إذا ((ادھار == 0 || ادھار == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		ادھار = 16;
	}
	إذا (ادھار == 0)
		ادھار = c == '0' ? 8 : 10;

	cutoff = ULONG_MAX / (بنانشانی لما)ادھار;
	cutlim = ULONG_MAX % (بنانشانی لما)ادھار;
	لكل (acc = 0, any = 0;; c = (بنانشانی حرف) *s++) {
		إذا (ہندسہ_اے(c))
			c -= '0';
		وإلا إذا (حرف_اے(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		وإلا
			اكسر;
		إذا (c >= ادھار)
			اكسر;
		إذا (any < 0)
			استمر;
		إذا (acc > cutoff || acc == cutoff && c > cutlim) {
			any = -1;
			acc = ULONG_MAX;
			errno = ERANGE;
		} وإلا {
			any = 1;
			acc *= (بنانشانی لما)ادھار;
			acc += c;
		}
	}
	إذا (neg && any > 0)
		acc = -acc;
	إذا (endptr != 0)
		*endptr = (حرف *) (any ? s - 1 : nptr);
	أرجع (acc);
}
#جے_انت /* !HAVE_STRTOUL */
