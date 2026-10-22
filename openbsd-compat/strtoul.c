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
#ifndef HAVE_STRTOUL

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
अचिन्हित दीर्घ
म_से_अदीर्घ(स्थिरांक अक्षर *nptr, अक्षर **endptr, पूर्णांक base)
{
	स्थिरांक अक्षर *s;
	अचिन्हित दीर्घ acc, cutoff;
	पूर्णांक c;
	पूर्णांक neg, any, cutlim;

	/*
	 * See strtol for comments as to the logic used.
	 */
	s = nptr;
	करा {
		c = (अचिन्हित अक्षर) *s++;
	} पर्यंत (है_खाली(c));
	जर (c == '-') {
		neg = 1;
		c = *s++;
	} अन्यथा {
		neg = 0;
		जर (c == '+')
			c = *s++;
	}
	जर ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	जर (base == 0)
		base = c == '0' ? 8 : 10;

	cutoff = अच_दीर्घ_उच्च / (अचिन्हित दीर्घ)base;
	cutlim = अच_दीर्घ_उच्च % (अचिन्हित दीर्घ)base;
	साठी (acc = 0, any = 0;; c = (अचिन्हित अक्षर) *s++) {
		जर (है_अंक(c))
			c -= '0';
		अन्यथा जर (है_अक्षर(c))
			c -= है_बड़ा(c) ? 'A' - 10 : 'a' - 10;
		अन्यथा
			थांबा;
		जर (c >= base)
			थांबा;
		जर (any < 0)
			सुरूठेवा;
		जर (acc > cutoff || acc == cutoff && c > cutlim) {
			any = -1;
			acc = अच_दीर्घ_उच्च;
			त्रुटि_सं = दुस्फल;
		} अन्यथा {
			any = 1;
			acc *= (अचिन्हित दीर्घ)base;
			acc += c;
		}
	}
	जर (neg && any > 0)
		acc = -acc;
	जर (endptr != 0)
		*endptr = (अक्षर *) (any ? s - 1 : nptr);
	परत (acc);
}
#endif /* !HAVE_STRTOUL */
