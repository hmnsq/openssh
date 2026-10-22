/*	$OpenBSD: fnmatch.h,v 1.8 2005/12/13 00:35:22 millert Exp $	*/
/*	$NetBSD: fnmatch.h,v 1.5 1994/10/26 00:55:53 cgd Exp $	*/

/*-
 * Copyright (c) 1992, 1993
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
 *
 *	@(#)fnmatch.h	8.1 (Berkeley) 6/2/93
 */

/* OPENBSD ORIGINAL: include/fnmatch.h */

#اگر_غیر_تعریف_شدہ HAVE_FNMATCH_H
/* Ensure we define FNM_CASEFOLD */
#تعریف_کرو __BSD_VISIBLE 1

#اگر_غیر_تعریف_شدہ	_FNMATCH_H_
#تعریف_کرو	_FNMATCH_H_

#اگر_تعریف_شدہ HAVE_SYS_CDEFS_H
#شامل <sys/cdefs.h>
#اگر_ختم

#تعریف_کرو	FNM_NOMATCH	1	/* Match failed. */
#تعریف_کرو	FNM_NOSYS	2	/* Function not supported (unused). */

#تعریف_کرو	FNM_NOESCAPE	0x01	/* Disable backslash escaping. */
#تعریف_کرو	FNM_PATHNAME	0x02	/* Slash must be matched by slash. */
#تعریف_کرو	FNM_PERIOD	0x04	/* Period must be matched by period. */
#اگر __BSD_VISIBLE
#تعریف_کرو	FNM_LEADING_DIR	0x08	/* Ignore /<tail> after Imatch. */
#تعریف_کرو	FNM_CASEFOLD	0x10	/* Case insensitive search. */
#تعریف_کرو	FNM_IGNORECASE	FNM_CASEFOLD
#تعریف_کرو	FNM_FILE_NAME	FNM_PATHNAME
#اگر_ختم

/* __BEGIN_DECLS */
صحیح	 fnmatch(ثابت حرف *, ثابت حرف *, صحیح);
/* __END_DECLS */

#اگر_ختم /* !_FNMATCH_H_ */
#اگر_ختم /* ! HAVE_FNMATCH_H */
