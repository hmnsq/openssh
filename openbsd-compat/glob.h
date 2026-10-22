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

#अगर !defined(HAVE_GLOB_H) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#अगर_अघोषित _COMPAT_GLOB_H_
#घोषणा	_COMPAT_GLOB_H_

#समावेश <sys/stat.h>
#समावेश <sys/types.h>

# define glob_t _ssh_compat_glob_t
# define glob(a, b, c, d)  _ssh__compat_glob(a, b, c, d)
# define globfree(a)  _ssh__compat_globfree(a)

काष्ठा stat;
प्रकार काष्ठा {
	माप_प्रकार gl_pathc;	/* Count of total paths so far. */
	माप_प्रकार gl_matchc;	/* Count of paths matching pattern. */
	माप_प्रकार gl_offs;		/* Reserved at beginning of gl_pathv. */
	पूर्णांक gl_flags;		/* Copy of flags parameter to glob. */
	अक्षर **gl_pathv;	/* List of paths matching pattern. */
	काष्ठा stat **gl_statv;	/* Stat entries corresponding to gl_pathv */
				/* Copy of errfunc parameter to glob. */
	पूर्णांक (*gl_errfunc)(स्थिर अक्षर *, पूर्णांक);

	/*
	 * Alternate filesystem access methods for glob; replacement
	 * versions of closedir(3), readdir(3), opendir(3), stat(2)
	 * and lstat(2).
	 */
	व्योम (*gl_closedir)(व्योम *);
	काष्ठा dirent *(*gl_readdir)(व्योम *);	
	व्योम *(*gl_opendir)(स्थिर अक्षर *);
	पूर्णांक (*gl_lstat)(स्थिर अक्षर *, काष्ठा stat *);
	पूर्णांक (*gl_stat)(स्थिर अक्षर *, काष्ठा stat *);
} glob_t;

#घोषणा	GLOB_APPEND	0x0001	/* Append to output from previous call. */
#घोषणा	GLOB_DOOFFS	0x0002	/* Use gl_offs. */
#घोषणा	GLOB_ERR	0x0004	/* Return on error. */
#घोषणा	GLOB_MARK	0x0008	/* Append / to matching directories. */
#घोषणा	GLOB_NOCHECK	0x0010	/* Return pattern itself if nothing matches. */
#घोषणा	GLOB_NOSORT	0x0020	/* Don't sort. */
#घोषणा	GLOB_NOESCAPE	0x1000	/* Disable backslash escaping. */

#घोषणा	GLOB_NOSPACE	(-1)	/* Malloc call failed. */
#घोषणा	GLOB_ABORTED	(-2)	/* Unignored error. */
#घोषणा	GLOB_NOMATCH	(-3)	/* No match and GLOB_NOCHECK not set. */
#घोषणा	GLOB_NOSYS	(-4)	/* Function not supported. */

#घोषणा	GLOB_ALTDIRFUNC	0x0040	/* Use alternately specified directory funcs. */
#घोषणा	GLOB_BRACE	0x0080	/* Expand braces ala csh. */
#घोषणा	GLOB_MAGCHAR	0x0100	/* Pattern had globbing characters. */
#घोषणा	GLOB_NOMAGIC	0x0200	/* GLOB_NOCHECK without magic chars (csh). */
#घोषणा	GLOB_QUOTE	0x0400	/* Quote special chars with \. */
#घोषणा	GLOB_TILDE	0x0800	/* Expand tilde names from the passwd file. */
#घोषणा GLOB_LIMIT	0x2000	/* Limit pattern match output to ARG_MAX */
#घोषणा	GLOB_KEEPSTAT	0x4000	/* Retain stat data for paths in gl_statv. */
#घोषणा GLOB_ABEND	GLOB_ABORTED /* backward compatibility */

पूर्णांक	glob(स्थिर अक्षर *, पूर्णांक, पूर्णांक (*)(स्थिर अक्षर *, पूर्णांक), glob_t *);
व्योम	globfree(glob_t *);

#पूर्ण_अगर /* !_GLOB_H_ */

#पूर्ण_अगर /* !defined(HAVE_GLOB_H) || !defined(GLOB_HAS_ALTDIRFUNC)  ||
	  !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOH_HAS_GL_STATV) */

