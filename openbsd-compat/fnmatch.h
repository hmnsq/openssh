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

#నిర్వచితం_కాకపోతే HAVE_FNMATCH_H
/* Ensure we define FNM_CASEFOLD */
#నిర్వచించు __BSD_VISIBLE 1

#నిర్వచితం_కాకపోతే	_FNMATCH_H_
#నిర్వచించు	_FNMATCH_H_

#నిర్వచితమైతే HAVE_SYS_CDEFS_H
#అన్తర్భావ <sys/cdefs.h>
#అయితే_ముగింపు

#నిర్వచించు	FNM_NOMATCH	1	/* Match failed. */
#నిర్వచించు	FNM_NOSYS	2	/* Function not supported (unused). */

#నిర్వచించు	FNM_NOESCAPE	0x01	/* Disable backslash escaping. */
#నిర్వచించు	FNM_PATHNAME	0x02	/* Slash must be matched by slash. */
#నిర్వచించు	FNM_PERIOD	0x04	/* Period must be matched by period. */
#ఒకవేళ __BSD_VISIBLE
#నిర్వచించు	FNM_LEADING_DIR	0x08	/* Ignore /<tail> after Imatch. */
#నిర్వచించు	FNM_CASEFOLD	0x10	/* Case insensitive search. */
#నిర్వచించు	FNM_IGNORECASE	FNM_CASEFOLD
#నిర్వచించు	FNM_FILE_NAME	FNM_PATHNAME
#అయితే_ముగింపు

/* __BEGIN_DECLS */
పూర్ణాంకం	 fnmatch(స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
/* __END_DECLS */

#అయితే_ముగింపు /* !_FNMATCH_H_ */
#అయితే_ముగింపు /* ! HAVE_FNMATCH_H */
