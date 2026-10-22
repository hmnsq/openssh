/*	$OpenBSD: glob.h,v 1.14 2019/02/04 16:45:40 millert Exp $	*/
/*	$NetBSD: glob.h,v 1.5 1994/10/26 00:55:56 cgd Exp $	*/

/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Guido van Rossum.
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
 *	@(#)glob.h	8.1 (Berkeley) 6/2/93
 */

/* OPENBSD ORIGINAL: include/glob.h */

#ఒకవేళ !defined(HAVE_GLOB_H) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#నిర్వచితం_కాకపోతే _COMPAT_GLOB_H_
#నిర్వచించు	_COMPAT_GLOB_H_

#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/types.h>

# define glob_t _ssh_compat_glob_t
# define glob(a, b, c, d)  _ssh__compat_glob(a, b, c, d)
# define globfree(a)  _ssh__compat_globfree(a)

నిర్మాణం stat;
రకనిర్వచనం నిర్మాణం {
	కొలత_t gl_pathc;	/* Count of total paths so far. */
	కొలత_t gl_matchc;	/* Count of paths matching pattern. */
	కొలత_t gl_offs;		/* Reserved at beginning of gl_pathv. */
	పూర్ణాంకం gl_flags;		/* Copy of flags parameter to glob. */
	అక్షరం **gl_pathv;	/* List of paths matching pattern. */
	నిర్మాణం stat **gl_statv;	/* Stat entries corresponding to gl_pathv */
				/* Copy of errfunc parameter to glob. */
	పూర్ణాంకం (*gl_errfunc)(స్థిరరాశి అక్షరం *, పూర్ణాంకం);

	/*
	 * Alternate filesystem access methods for glob; replacement
	 * versions of closedir(3), readdir(3), opendir(3), stat(2)
	 * and lstat(2).
	 */
	శూన్య (*gl_closedir)(శూన్య *);
	నిర్మాణం dirent *(*gl_readdir)(శూన్య *);	
	శూన్య *(*gl_opendir)(స్థిరరాశి అక్షరం *);
	పూర్ణాంకం (*gl_lstat)(స్థిరరాశి అక్షరం *, నిర్మాణం stat *);
	పూర్ణాంకం (*gl_stat)(స్థిరరాశి అక్షరం *, నిర్మాణం stat *);
} glob_t;

#నిర్వచించు	GLOB_APPEND	0x0001	/* Append to output from previous call. */
#నిర్వచించు	GLOB_DOOFFS	0x0002	/* Use gl_offs. */
#నిర్వచించు	GLOB_ERR	0x0004	/* Return on error. */
#నిర్వచించు	GLOB_MARK	0x0008	/* Append / to matching directories. */
#నిర్వచించు	GLOB_NOCHECK	0x0010	/* Return pattern itself if nothing matches. */
#నిర్వచించు	GLOB_NOSORT	0x0020	/* Don't sort. */
#నిర్వచించు	GLOB_NOESCAPE	0x1000	/* Disable backslash escaping. */

#నిర్వచించు	GLOB_NOSPACE	(-1)	/* Malloc call failed. */
#నిర్వచించు	GLOB_ABORTED	(-2)	/* Unignored error. */
#నిర్వచించు	GLOB_NOMATCH	(-3)	/* No match and GLOB_NOCHECK not set. */
#నిర్వచించు	GLOB_NOSYS	(-4)	/* Function not supported. */

#నిర్వచించు	GLOB_ALTDIRFUNC	0x0040	/* Use alternately specified directory funcs. */
#నిర్వచించు	GLOB_BRACE	0x0080	/* Expand braces ala csh. */
#నిర్వచించు	GLOB_MAGCHAR	0x0100	/* Pattern had globbing characters. */
#నిర్వచించు	GLOB_NOMAGIC	0x0200	/* GLOB_NOCHECK without magic chars (csh). */
#నిర్వచించు	GLOB_QUOTE	0x0400	/* Quote special chars with \. */
#నిర్వచించు	GLOB_TILDE	0x0800	/* Expand tilde names from the passwd file. */
#నిర్వచించు GLOB_హద్దు	0x2000	/* Limit pattern match output to ARG_MAX */
#నిర్వచించు	GLOB_KEEPSTAT	0x4000	/* Retain stat data for paths in gl_statv. */
#నిర్వచించు GLOB_ABEND	GLOB_ABORTED /* backward compatibility */

పూర్ణాంకం	glob(స్థిరరాశి అక్షరం *, పూర్ణాంకం, పూర్ణాంకం (*)(స్థిరరాశి అక్షరం *, పూర్ణాంకం), glob_t *);
శూన్య	globfree(glob_t *);

#అయితే_ముగింపు /* !_GLOB_H_ */

#అయితే_ముగింపు /* !defined(HAVE_GLOB_H) || !defined(GLOB_HAS_ALTDIRFUNC)  ||
	  !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOH_HAS_GL_STATV) */

