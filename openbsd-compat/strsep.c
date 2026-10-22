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

#অন্তর্ভাব "includes.h"

#যদি !defined(HAVE_STRSEP)

#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdio.h>

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
বর্ণ *
strsep(বর্ণ **stringp, ধ্রুব বর্ণ *delim)
{
	বর্ণ *s;
	ধ্রুব বর্ণ *spanp;
	পূর্ণাঙ্ক c, sc;
	বর্ণ *tok;

	যদি ((s = *stringp) == রিক্ত)
		প্রত্যাগম (রিক্ত);
	প্রতি (tok = s;;) {
		c = *s++;
		spanp = delim;
		কুরু {
			যদি ((sc = *spanp++) == c) {
				যদি (c == 0)
					s = রিক্ত;
				অন্যথা
					s[-1] = 0;
				*stringp = s;
				প্রত্যাগম (tok);
			}
		} যাবত্ (sc != 0);
	}
	/* NOTREACHED */
}

#endif /* !defined(HAVE_STRSEP) */
