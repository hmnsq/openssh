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

#अन्तर्भाव "includes.h"
#यदि_अपरिभाषितम् HAVE_STRTOUL

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdlib.h>

/*
 * Convert a string to an unsigned long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
अचिह्नित दीर्घ
strtoul(ध्रुव वर्ण *nptr, वर्ण **endptr, पूर्णाङ्क आधारः)
{
	ध्रुव वर्ण *s;
	अचिह्नित दीर्घ acc, cutoff;
	पूर्णाङ्क c;
	पूर्णाङ्क neg, any, cutlim;

	/*
	 * See strtol for comments as to the logic used.
	 */
	s = nptr;
	कुरु {
		c = (अचिह्नित वर्ण) *s++;
	} यावत् (रिक्तम्_वा(c));
	यदि (c == '-') {
		neg = 1;
		c = *s++;
	} अन्यथा {
		neg = 0;
		यदि (c == '+')
			c = *s++;
	}
	यदि ((आधारः == 0 || आधारः == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		आधारः = 16;
	}
	यदि (आधारः == 0)
		आधारः = c == '0' ? 8 : 10;

	cutoff = ULONG_MAX / (अचिह्नित दीर्घ)आधारः;
	cutlim = ULONG_MAX % (अचिह्नित दीर्घ)आधारः;
	प्रति (acc = 0, any = 0;; c = (अचिह्नित वर्ण) *s++) {
		यदि (अङ्कः_वा(c))
			c -= '0';
		अन्यथा यदि (अक्षरम्_वा(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		अन्यथा
			भङ्ग;
		यदि (c >= आधारः)
			भङ्ग;
		यदि (any < 0)
			अनुवर्त;
		यदि (acc > cutoff || acc == cutoff && c > cutlim) {
			any = -1;
			acc = ULONG_MAX;
			errno = ERANGE;
		} अन्यथा {
			any = 1;
			acc *= (अचिह्नित दीर्घ)आधारः;
			acc += c;
		}
	}
	यदि (neg && any > 0)
		acc = -acc;
	यदि (endptr != 0)
		*endptr = (वर्ण *) (any ? s - 1 : nptr);
	प्रत्यागम (acc);
}
#यदि_अन्तः /* !HAVE_STRTOUL */
