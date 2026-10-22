/*	$OpenBSD: strsep.c,v 1.6 2005/08/08 08:05:37 espie Exp $	*/

/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
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

/* OPENBSD ORIGINAL: lib/libc/string/strsep.c */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି !defined(HAVE_STRSEP)

#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

/*
 * Get next token from string *stringp, where tokens are possibly-empty
 * strings separated by characters from delim.  
 *
 * Writes NULs into the string at *stringp to end tokens.
 * delim need not remain constant from call to call.
 * On return, *stringp points past the last NUL written (if there might
 * be further tokens), or is NULL (if there are definitely no more tokens).
 *
 * If *stringp is NULL, strsep returns NULL.
 */
ଅକ୍ଷର *
strsep(ଅକ୍ଷର **stringp, ଅଚଳ ଅକ୍ଷର *delim)
{
	ଅକ୍ଷର *s;
	ଅଚଳ ଅକ୍ଷର *spanp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c, sc;
	ଅକ୍ଷର *tok;

	ଯଦି ((s = *stringp) == ଖାଲି)
		ଫେରନ୍ତୁ (ଖାଲି);
	ପାଇଁ (tok = s;;) {
		c = *s++;
		spanp = delim;
		କର {
			ଯଦି ((sc = *spanp++) == c) {
				ଯଦି (c == 0)
					s = ଖାଲି;
				ଅନ୍ୟଥା
					s[-1] = 0;
				*stringp = s;
				ଫେରନ୍ତୁ (tok);
			}
		} ଯେତେବେଳେ (sc != 0);
	}
	/* NOTREACHED */
}

#endif /* !defined(HAVE_STRSEP) */
