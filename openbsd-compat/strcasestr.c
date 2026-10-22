/*	$OpenBSD: strcasestr.c,v 1.4 2015/08/31 02:53:57 guenther Exp $	*/
/*	$NetBSD: strcasestr.c,v 1.2 2005/02/09 21:35:47 kleink Exp $	*/

/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
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

/* OPENBSD ORIGINAL: lib/libc/string/strcasestr.c */

#شامل "includes.h"

#اگر_غیر_تعریف_شدہ HAVE_STRCASESTR

#شامل <ctype.h>
#شامل <string.h>

/*
 * Find the first occurrence of find in s, ignore case.
 */
حرف *
strcasestr(ثابت حرف *s, ثابت حرف *ڈھونڈو)
{
	حرف c, sc;
	سائز_t len;

	اگر ((c = *ڈھونڈو++) != 0) {
		c = (حرف)tolower((غیرعلامتی حرف)c);
		len = لڑی_لمبائی(ڈھونڈو);
		کرو {
			کرو {
				اگر ((sc = *s++) == 0)
					واپس (تہی);
			} جب ((حرف)tolower((غیرعلامتی حرف)sc) != c);
		} جب (strncasecmp(s, ڈھونڈو, len) != 0);
		s--;
	}
	واپس ((حرف *)s);
}
DEF_WEAK(strcasestr);

#اگر_ختم
