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

#అన్తర్భావ "includes.h"
#నిర్వచితం_కాకపోతే HAVE_STRTOULL

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdlib.h>

/*
 * Convert a string to an unsigned long long.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
గుర్తులేని దీర్ఘ దీర్ఘ
strtoull(స్థిరరాశి అక్షరం *nptr, అక్షరం **endptr, పూర్ణాంకం పునాది)
{
	స్థిరరాశి అక్షరం *s;
	గుర్తులేని దీర్ఘ దీర్ఘ acc, cutoff;
	పూర్ణాంకం c;
	పూర్ణాంకం neg, any, cutlim;

	/*
	 * See strtoq for comments as to the logic used.
	 */
	s = nptr;
	చేయి {
		c = (గుర్తులేని అక్షరం) *s++;
	} అయితే (ఖాళీనా(c));
	ఒకవేళ (c == '-') {
		neg = 1;
		c = *s++;
	} లేకపోతే { 
		neg = 0;
		ఒకవేళ (c == '+')
			c = *s++;
	}
	ఒకవేళ ((పునాది == 0 || పునాది == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		పునాది = 16;
	}
	ఒకవేళ (పునాది == 0)
		పునాది = c == '0' ? 8 : 10;

	cutoff = ULLONG_MAX / (గుర్తులేని దీర్ఘ దీర్ఘ)పునాది;
	cutlim = ULLONG_MAX % (గుర్తులేని దీర్ఘ దీర్ఘ)పునాది;
	కొరకు (acc = 0, any = 0;; c = (గుర్తులేని అక్షరం) *s++) {
		ఒకవేళ (అంకెనా(c))
			c -= '0';
		లేకపోతే ఒకవేళ (అక్షరమా(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		లేకపోతే
			ఆపు;
		ఒకవేళ (c >= పునాది)
			ఆపు;
		ఒకవేళ (any < 0)
			కొనసాగు;
		ఒకవేళ (acc > cutoff || (acc == cutoff && c > cutlim)) {
			any = -1;
			acc = ULLONG_MAX;
			errno = ERANGE;
		} లేకపోతే {
			any = 1;
			acc *= (గుర్తులేని దీర్ఘ దీర్ఘ)పునాది;
			acc += c;
		}
	}
	ఒకవేళ (neg && any > 0)
		acc = -acc;
	ఒకవేళ (endptr != 0)
		*endptr = (అక్షరం *) (any ? s - 1 : nptr);
	తిరిగి (acc);
}
#అయితే_ముగింపు /* !HAVE_STRTOULL */
