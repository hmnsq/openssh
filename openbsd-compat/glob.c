/*	$OpenBSD: glob.c,v 1.49 2020/04/21 08:25:22 dtucker Exp $ */
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
 */

/* OPENBSD ORIGINAL: lib/libc/gen/glob.c */

/*
 * glob(3) -- a superset of the one defined in POSIX 1003.2.
 *
 * The [!...] convention to negate a range is supported (SysV, Posix, ksh).
 *
 * Optional extra services, controlled by flags not defined by POSIX:
 *
 * GLOB_QUOTE:
 *	Escaping convention: \ inhibits any special meaning the following
 *	character might have (except \ at end of string is retained).
 * GLOB_MAGCHAR:
 *	Set in gl_flags if pattern contained a globbing character.
 * GLOB_NOMAGIC:
 *	Same as GLOB_NOCHECK, but it will only append pattern if it did
 *	not contain any magic characters.  [Used in csh style globbing]
 * GLOB_ALTDIRFUNC:
 *	Use alternately specified directory access functions.
 * GLOB_TILDE:
 *	expand ~user/foo to the /home/dir/of/user/foo
 * GLOB_BRACE:
 *	expand {1,2}{a,b} to 1a 1b 2a 2b
 * gl_matchc:
 *	Number of matches in the current invocation of glob.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ "glob.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <dirent.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಯದಿ !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#ಅನ್ತರ್ಭಾವ "charclass.h"

#ifdef TILDE
# undef TILDE
#endif

#define	DOLLAR		'$'
#define	DOT		'.'
#define	EOS		'\0'
#define	LBRACKET	'['
#define	NOT		'!'
#define	QUESTION	'?'
#define	QUOTE		'\\'
#define	RANGE		'-'
#define	RBRACKET	']'
#define	SEP		'/'
#define	STAR		'*'
#define	TILDE		'~'
#define	UNDERSCORE	'_'
#define	LBRACE		'{'
#define	RBRACE		'}'
#define	SLASH		'/'
#define	COMMA		','

#ifndef DEBUG

#define	M_QUOTE		0x8000
#define	M_PROTECT	0x4000
#define	M_MASK		0xffff
#define	M_ASCII		0x00ff

ಪ್ರಕಾರನಿರ್ದೇಶ u_short Char;

#ಅನ್ಯಥಾ

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

ಪ್ರಕಾರನಿರ್ದೇಶ ವರ್ಣ Char;

#endif


#define	CHAR(c)		((Char)((c)&M_ASCII))
#define	META(c)		((Char)((c)|M_QUOTE))
#define	M_ALL		META('*')
#define	M_END		META(']')
#define	M_NOT		META('!')
#define	M_ONE		META('?')
#define	M_RNG		META('-')
#define	M_SET		META('[')
#define	M_CLASS		META(':')
#define	ismeta(c)	(((c)&M_QUOTE) != 0)

#define	GLOB_LIMIT_MALLOC	65536
#define	GLOB_LIMIT_STAT		2048
#define	GLOB_LIMIT_READDIR	16384

ಸಂರಚನಾ glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

ಸಂರಚನಾ glob_path_stat {
	ವರ್ಣ		*gps_path;
	ಸಂರಚನಾ stat	*gps_stat;
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 compare(ಧ್ರುವ ಶೂನ್ಯ *, ಧ್ರುವ ಶೂನ್ಯ *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 compare_gps(ಧ್ರುವ ಶೂನ್ಯ *, ಧ್ರುವ ಶೂನ್ಯ *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 g_Ctoc(ಧ್ರುವ Char *, ವರ್ಣ *, size_t);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 g_lstat(Char *, ಸಂರಚನಾ stat *, glob_t *);
ಸ್ಥಿರ DIR	*g_opendir(Char *, glob_t *);
ಸ್ಥಿರ Char	*g_strchr(ಧ್ರುವ Char *, ಪೂರ್ಣಾಙ್ಕ);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 g_strncmp(ಧ್ರುವ Char *, ಧ್ರುವ ವರ್ಣ *, size_t);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 g_stat(Char *, ಸಂರಚನಾ stat *, glob_t *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 glob0(ಧ್ರುವ Char *, glob_t *, ಸಂರಚನಾ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 glob1(Char *, Char *, glob_t *, ಸಂರಚನಾ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, ಸಂರಚನಾ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, ಸಂರಚನಾ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 globextend(ಧ್ರುವ Char *, glob_t *, ಸಂರಚನಾ glob_lim *,
		    ಸಂರಚನಾ stat *);
ಸ್ಥಿರ ಧ್ರುವ Char *
		 globtilde(ಧ್ರುವ Char *, Char *, size_t, glob_t *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 globexp1(ಧ್ರುವ Char *, glob_t *, ಸಂರಚನಾ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 globexp2(ಧ್ರುವ Char *, ಧ್ರುವ Char *, glob_t *,
		    ಸಂರಚನಾ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 match(Char *, Char *, Char *);
#ifdef DEBUG
ಸ್ಥಿರ ಶೂನ್ಯ	 qprintf(ಧ್ರುವ ವರ್ಣ *, Char *);
#endif

ಪೂರ್ಣಾಙ್ಕ
glob(ಧ್ರುವ ವರ್ಣ *pattern, ಪೂರ್ಣಾಙ್ಕ flags, ಪೂರ್ಣಾಙ್ಕ (*errfunc)(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ),
    glob_t *pglob)
{
	ಧ್ರುವ u_char *patnext;
	ಪೂರ್ಣಾಙ್ಕ c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	ಸಂರಚನಾ glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	ಯದಿ (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = ರಿಕ್ತ;
		pglob->gl_statv = ರಿಕ್ತ;
		ಯದಿ (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	ಯದಿ (strnlen(pattern, PATH_MAX) == PATH_MAX)
		ಪ್ರತ್ಯಾಗಮ(GLOB_NOMATCH);

	ಯದಿ (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		ಪ್ರತ್ಯಾಗಮ GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	ಯದಿ (flags & GLOB_NOESCAPE)
		ಯಾವತ್ (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	ಅನ್ಯಥಾ {
		/* Protect the quoted characters. */
		ಯಾವತ್ (bufnext < bufend && (c = *patnext++) != EOS)
			ಯದಿ (c == QUOTE) {
				ಯದಿ ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} ಅನ್ಯಥಾ
				*bufnext++ = c;
	}
	*bufnext = EOS;

	ಯದಿ (flags & GLOB_BRACE)
		ಪ್ರತ್ಯಾಗಮ globexp1(patbuf, pglob, &limit);
	ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
globexp1(ಧ್ರುವ Char *pattern, glob_t *pglob, ಸಂರಚನಾ glob_lim *limitp)
{
	ಧ್ರುವ Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	ಯದಿ (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		ಪ್ರತ್ಯಾಗಮ glob0(pattern, pglob, limitp);

	ಯದಿ ((ptr = (ಧ್ರುವ Char *) g_strchr(ptr, LBRACE)) != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ globexp2(ptr, pattern, pglob, limitp);

	ಪ್ರತ್ಯಾಗಮ glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
globexp2(ಧ್ರುವ Char *ptr, ಧ್ರುವ Char *pattern, glob_t *pglob,
    ಸಂರಚನಾ glob_lim *limitp)
{
	ಪೂರ್ಣಾಙ್ಕ     i, rv;
	Char   *lm, *ls;
	ಧ್ರುವ Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	ಪ್ರತಿ (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	ಪ್ರತಿ (i = 0, pe = ++ptr; *pe; pe++)
		ಯದಿ (*pe == LBRACKET) {
			/* Ignore everything between [] */
			ಪ್ರತಿ (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			ಯದಿ (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} ಅನ್ಯಥಾ ಯದಿ (*pe == LBRACE)
			i++;
		ಅನ್ಯಥಾ ಯದಿ (*pe == RBRACE) {
			ಯದಿ (i == 0)
				ಭಙ್ಗ;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	ಯದಿ (i != 0 || *pe == EOS)
		ಪ್ರತ್ಯಾಗಮ glob0(patbuf, pglob, limitp);

	ಪ್ರತಿ (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		ವಿಕಲ್ಪ (*pm) {
		ಪಕ್ಷ LBRACKET:
			/* Ignore everything between [] */
			ಪ್ರತಿ (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			ಯದಿ (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			ಭಙ್ಗ;

		ಪಕ್ಷ LBRACE:
			i++;
			ಭಙ್ಗ;

		ಪಕ್ಷ RBRACE:
			ಯದಿ (i) {
				i--;
				ಭಙ್ಗ;
			}
			/* FALLTHROUGH */
		ಪಕ್ಷ COMMA:
			ಯದಿ (i && *pm == COMMA)
				ಭಙ್ಗ;
			ಅನ್ಯಥಾ {
				/* Append the current string */
				ಪ್ರತಿ (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				ಪ್ರತಿ (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				ಯದಿ (rv && rv != GLOB_NOMATCH)
					ಪ್ರತ್ಯಾಗಮ rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			ಭಙ್ಗ;

		ಸ್ವಭಾವ:
			ಭಙ್ಗ;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}



/*
 * expand tilde from the passwd file.
 */
ಸ್ಥಿರ ಧ್ರುವ Char *
globtilde(ಧ್ರುವ Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	ಸಂರಚನಾ passwd *pwd;
	ವರ್ಣ *h;
	ಧ್ರುವ Char *p;
	Char *b, *eb;

	ಯದಿ (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		ಪ್ರತ್ಯಾಗಮ pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	ಪ್ರತಿ (p = pattern + 1, h = (ವರ್ಣ *) patbuf;
	    h < (ವರ್ಣ *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#ಯದಿ 0
	ಯದಿ (h == (ವರ್ಣ *)eb)
		ಪ್ರತ್ಯಾಗಮ what;
#endif

	ಯದಿ (((ವರ್ಣ *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#ಯದಿ 0
		ಯದಿ (issetugid() != 0 || (h = getenv("HOME")) == ರಿಕ್ತ) {
#endif
		ಯದಿ ((getuid() != geteuid()) || (h = getenv("HOME")) == ರಿಕ್ತ) {
			ಯದಿ ((pwd = getpwuid(getuid())) == ರಿಕ್ತ)
				ಪ್ರತ್ಯಾಗಮ pattern;
			ಅನ್ಯಥಾ
				h = pwd->pw_dir;
		}
	} ಅನ್ಯಥಾ {
		/*
		 * Expand a ~user
		 */
		ಯದಿ ((pwd = getpwnam((ವರ್ಣ*) patbuf)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ pattern;
		ಅನ್ಯಥಾ
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	ಪ್ರತಿ (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	ಯಾವತ್ (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	ಪ್ರತ್ಯಾಗಮ patbuf;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
g_strncmp(ಧ್ರುವ Char *s1, ಧ್ರುವ ವರ್ಣ *s2, size_t n)
{
	ಪೂರ್ಣಾಙ್ಕ rv = 0;

	ಯಾವತ್ (n--) {
		rv = *(Char *)s1 - *(ಧ್ರುವ unsigned ವರ್ಣ *)s2++;
		ಯದಿ (rv)
			ಭಙ್ಗ;
		ಯದಿ (*s1++ == '\0')
			ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ rv;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
g_charclass(ಧ್ರುವ Char **patternp, Char **bufnextp)
{
	ಧ್ರುವ Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	ಧ್ರುವ Char *colon;
	ಸಂರಚನಾ cclass *cc;
	size_t len;

	ಯದಿ ((colon = g_strchr(pattern, ':')) == ರಿಕ್ತ || colon[1] != ']')
		ಪ್ರತ್ಯಾಗಮ 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	ಪ್ರತಿ (cc = cclasses; cc->name != ರಿಕ್ತ; cc++) {
		ಯದಿ (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			ಭಙ್ಗ;
	}
	ಯದಿ (cc->name == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
glob0(ಧ್ರುವ Char *pattern, glob_t *pglob, ಸಂರಚನಾ glob_lim *limitp)
{
	ಧ್ರುವ Char *qpatnext;
	ಪೂರ್ಣಾಙ್ಕ c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	ಯಾವತ್ ((c = *qpatnext++) != EOS) {
		ವಿಕಲ್ಪ (c) {
		ಪಕ್ಷ LBRACKET:
			c = *qpatnext;
			ಯದಿ (c == NOT)
				++qpatnext;
			ಯದಿ (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == ರಿಕ್ತ) {
				*bufnext++ = LBRACKET;
				ಯದಿ (c == NOT)
					--qpatnext;
				ಭಙ್ಗ;
			}
			*bufnext++ = M_SET;
			ಯದಿ (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			ಕುರು {
				ಯದಿ (c == LBRACKET && *qpatnext == ':') {
					ಕುರು {
						err = g_charclass(&qpatnext,
						    &bufnext);
						ಯದಿ (err)
							ಭಙ್ಗ;
						c = *qpatnext++;
					} ಯಾವತ್ (c == LBRACKET && *qpatnext == ':');
					ಯದಿ (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						ಪ್ರತ್ಯಾಗಮ GLOB_NOMATCH;
					ಯದಿ (c == RBRACKET)
						ಭಙ್ಗ;
				}
				*bufnext++ = CHAR(c);
				ಯದಿ (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} ಯಾವತ್ ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			ಭಙ್ಗ;
		ಪಕ್ಷ QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			ಭಙ್ಗ;
		ಪಕ್ಷ STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			ಯದಿ (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			*bufnext++ = CHAR(c);
			ಭಙ್ಗ;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	ಯದಿ ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		ಪ್ರತ್ಯಾಗಮ(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	ಯದಿ (pglob->gl_pathc == oldpathc) {
		ಯದಿ ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			ಪ್ರತ್ಯಾಗಮ(globextend(pattern, pglob, limitp, ರಿಕ್ತ));
		ಅನ್ಯಥಾ
			ಪ್ರತ್ಯಾಗಮ(GLOB_NOMATCH);
	}
	ಯದಿ (!(pglob->gl_flags & GLOB_NOSORT)) {
		ಯದಿ ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			ಸಂರಚನಾ glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			ಯದಿ ((path_stat = calloc(n, ಪರಿಮಾಣ(*path_stat))) == ರಿಕ್ತ)
				ಪ್ರತ್ಯಾಗಮ GLOB_NOSPACE;
			ಪ್ರತಿ (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, ಪರಿಮಾಣ(*path_stat), compare_gps);
			ಪ್ರತಿ (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			ಮುಕ್ತ(path_stat);
		} ಅನ್ಯಥಾ {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, ಪರಿಮಾಣ(ವರ್ಣ *),
			    compare);
		}
	}
	ಪ್ರತ್ಯಾಗಮ(0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
compare(ಧ್ರುವ ಶೂನ್ಯ *p, ಧ್ರುವ ಶೂನ್ಯ *q)
{
	ಪ್ರತ್ಯಾಗಮ(strcmp(*(ವರ್ಣ **)p, *(ವರ್ಣ **)q));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
compare_gps(ಧ್ರುವ ಶೂನ್ಯ *_p, ಧ್ರುವ ಶೂನ್ಯ *_q)
{
	ಧ್ರುವ ಸಂರಚನಾ glob_path_stat *p = (ಧ್ರುವ ಸಂರಚನಾ glob_path_stat *)_p;
	ಧ್ರುವ ಸಂರಚನಾ glob_path_stat *q = (ಧ್ರುವ ಸಂರಚನಾ glob_path_stat *)_q;

	ಪ್ರತ್ಯಾಗಮ(strcmp(p->gps_path, q->gps_path));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, ಸಂರಚನಾ glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	ಯದಿ (*pattern == EOS)
		ಪ್ರತ್ಯಾಗಮ(0);
	ಪ್ರತ್ಯಾಗಮ(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, ಸಂರಚನಾ glob_lim *limitp)
{
	ಸಂರಚನಾ stat sb;
	Char *p, *q;
	ಪೂರ್ಣಾಙ್ಕ anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	ಪ್ರತಿ (anymeta = 0;;) {
		ಯದಿ (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			ಯದಿ ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				ಪ್ರತ್ಯಾಗಮ(GLOB_NOSPACE);
			}
			ಯದಿ (g_lstat(pathbuf, &sb, pglob))
				ಪ್ರತ್ಯಾಗಮ(0);

			ಯದಿ (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				ಯದಿ (pathend+1 > pathend_last)
					ಪ್ರತ್ಯಾಗಮ (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			ಪ್ರತ್ಯಾಗಮ(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		ಯಾವತ್ (*p != EOS && *p != SEP) {
			ಯದಿ (ismeta(*p))
				anymeta = 1;
			ಯದಿ (q+1 > pathend_last)
				ಪ್ರತ್ಯಾಗಮ (1);
			*q++ = *p++;
		}

		ಯದಿ (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			ಯಾವತ್ (*pattern == SEP) {
				ಯದಿ (pathend+1 > pathend_last)
					ಪ್ರತ್ಯಾಗಮ (1);
				*pathend++ = *pattern++;
			}
		} ಅನ್ಯಥಾ
			/* Need expansion, recurse. */
			ಪ್ರತ್ಯಾಗಮ(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    ಸಂರಚನಾ glob_lim *limitp)
{
	ಸಂರಚನಾ dirent *dp;
	DIR *dirp;
	ಪೂರ್ಣಾಙ್ಕ err;
	ವರ್ಣ buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	ಸಂರಚನಾ dirent *(*readdirfunc)(ಶೂನ್ಯ *);

	ಯದಿ (pathend > pathend_last)
		ಪ್ರತ್ಯಾಗಮ (1);
	*pathend = EOS;
	errno = 0;

	ಯದಿ ((dirp = g_opendir(pathbuf, pglob)) == ರಿಕ್ತ) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		ಯದಿ (pglob->gl_errfunc) {
			ಯದಿ (g_Ctoc(pathbuf, buf, ಪರಿಮಾಣ(buf)))
				ಪ್ರತ್ಯಾಗಮ(GLOB_ABORTED);
			ಯದಿ (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				ಪ್ರತ್ಯಾಗಮ(GLOB_ABORTED);
		}
		ಪ್ರತ್ಯಾಗಮ(0);
	}

	err = 0;

	/* Search directory for matching names. */
	ಯದಿ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	ಅನ್ಯಥಾ
		readdirfunc = (ಸಂರಚನಾ dirent *(*)(ಶೂನ್ಯ *))readdir;
	ಯಾವತ್ ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		ಯದಿ ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			ಭಙ್ಗ;
		}

		/* Initial DOT must be matched literally. */
		ಯದಿ (dp->d_name[0] == DOT && *pattern != DOT)
			ಅನುವರ್ತ;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		ಯಾವತ್ (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		ಯದಿ (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			ಭಙ್ಗ;
		}

		ಯದಿ (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			ಅನುವರ್ತ;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		ಯದಿ (err)
			ಭಙ್ಗ;
	}

	ಯದಿ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	ಅನ್ಯಥಾ
		closedir(dirp);
	ಪ್ರತ್ಯಾಗಮ(err);
}


/*
 * Extend the gl_pathv member of a glob_t structure to accommodate a new item,
 * add the new item, and update gl_pathc.
 *
 * This assumes the BSD realloc, which only copies the block when its size
 * crosses a power-of-two boundary; for v7 realloc, this would cause quadratic
 * behavior.
 *
 * Return 0 if new item added, error code if memory couldn't be allocated.
 *
 * Invariant of the glob_t structure:
 *	Either gl_pathc is zero and gl_pathv is NULL; or gl_pathc > 0 and
 *	gl_pathv points to (gl_offs + gl_pathc + 1) items.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
globextend(ಧ್ರುವ Char *path, glob_t *pglob, ಸಂರಚನಾ glob_lim *limitp,
    ಸಂರಚನಾ stat *sb)
{
	ವರ್ಣ **pathv;
	size_t i, newn, len;
	ವರ್ಣ *copy = ರಿಕ್ತ;
	ಧ್ರುವ Char *p;
	ಸಂರಚನಾ stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	ಯದಿ (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / ಪರಿಮಾಣ(*pathv) <= newn ||
	    SIZE_MAX / ಪರಿಮಾಣ(*statv) <= newn) {
 nospace:
		ಪ್ರತಿ (i = pglob->gl_offs; i < newn - 2; i++) {
			ಯದಿ (pglob->gl_pathv && pglob->gl_pathv[i])
				ಮುಕ್ತ(pglob->gl_pathv[i]);
			ಯದಿ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				ಮುಕ್ತ(pglob->gl_statv[i]);
		}
		ಮುಕ್ತ(pglob->gl_pathv);
		pglob->gl_pathv = ರಿಕ್ತ;
		ಮುಕ್ತ(pglob->gl_statv);
		pglob->gl_statv = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, ಪರಿಮಾಣ(*pathv));
	ಯದಿ (pathv == ರಿಕ್ತ)
		ಗಚ್ಛ nospace;
	ಯದಿ (pglob->gl_pathv == ರಿಕ್ತ && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		ಪ್ರತಿ (i = pglob->gl_offs; i > 0; i--)
			*--pathv = ರಿಕ್ತ;
	}
	pglob->gl_pathv = pathv;

	ಯದಿ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, ಪರಿಮಾಣ(*statv));
		ಯದಿ (statv == ರಿಕ್ತ)
			ಗಚ್ಛ nospace;
		ಯದಿ (pglob->gl_statv == ರಿಕ್ತ && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			ಪ್ರತಿ (i = pglob->gl_offs; i > 0; i--)
				*--statv = ರಿಕ್ತ;
		}
		pglob->gl_statv = statv;
		ಯದಿ (sb == ರಿಕ್ತ)
			statv[pglob->gl_offs + pglob->gl_pathc] = ರಿಕ್ತ;
		ಅನ್ಯಥಾ {
			limitp->glim_malloc += ಪರಿಮಾಣ(**statv);
			ಯದಿ ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				ಪ್ರತ್ಯಾಗಮ(GLOB_NOSPACE);
			}
			ಯದಿ ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(ಪರಿಮಾಣ(**statv))) == ರಿಕ್ತ)
				ಗಚ್ಛ copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    ಪರಿಮಾಣ(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = ರಿಕ್ತ;
	}

	ಪ್ರತಿ (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	ಯದಿ ((copy = malloc(len)) != ರಿಕ್ತ) {
		ಯದಿ (g_Ctoc(path, copy, len)) {
			ಮುಕ್ತ(copy);
			ಪ್ರತ್ಯಾಗಮ(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = ರಿಕ್ತ;

	ಯದಿ ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * ಪರಿಮಾಣ(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		ಪ್ರತ್ಯಾಗಮ(GLOB_NOSPACE);
	}
 copy_error:
	ಪ್ರತ್ಯಾಗಮ(copy == ರಿಕ್ತ ? GLOB_NOSPACE : 0);
}


/*
 * pattern matching function for filenames.  Each occurrence of the *
 * pattern causes an iteration.
 *
 * Note, this function differs from the original as per the discussion
 * here: https://research.swtch.com/glob
 *
 * Basically we removed the recursion and made it use the algorithm
 * from Russ Cox to not go quadratic on cases like a file called
 * ("a" x 100) . "x" matched against a pattern like "a*a*a*a*a*a*a*y".
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
match(Char *name, Char *pat, Char *patend)
{
	ಪೂರ್ಣಾಙ್ಕ ok, negate_range;
	Char c, k;
	Char *nextp = ರಿಕ್ತ;
	Char *nextn = ರಿಕ್ತ;

loop:
	ಯಾವತ್ (pat < patend) {
		c = *pat++;
		ವಿಕಲ್ಪ (c & M_MASK) {
		ಪಕ್ಷ M_ALL:
			ಯಾವತ್ (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			ಯದಿ (pat == patend)
				ಪ್ರತ್ಯಾಗಮ(1);
			ಯದಿ (*name == EOS)
				ಪ್ರತ್ಯಾಗಮ(0);
			nextn = name + 1;
			nextp = pat - 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ M_ONE:
			ಯದಿ (*name++ == EOS)
				ಗಚ್ಛ fail;
			ಭಙ್ಗ;
		ಪಕ್ಷ M_SET:
			ok = 0;
			ಯದಿ ((k = *name++) == EOS)
				ಗಚ್ಛ fail;
			ಯದಿ ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			ಯಾವತ್ (((c = *pat++) & M_MASK) != M_END) {
				ಯದಿ ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					ಯದಿ (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				ಯದಿ ((*pat & M_MASK) == M_RNG) {
					ಯದಿ (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} ಅನ್ಯಥಾ ಯದಿ (c == k)
					ok = 1;
			}
			ಯದಿ (ok == negate_range)
				ಗಚ್ಛ fail;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಯದಿ (*name++ != c)
				ಗಚ್ಛ fail;
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (*name == EOS)
		ಪ್ರತ್ಯಾಗಮ(1);

fail:
	ಯದಿ (nextn) {
		pat = nextp;
		name = nextn;
		ಗಚ್ಛ loop;
	}
	ಪ್ರತ್ಯಾಗಮ(0);
}

/* Free allocated data belonging to a glob_t structure. */
ಶೂನ್ಯ
globfree(glob_t *pglob)
{
	size_t i;
	ವರ್ಣ **pp;

	ಯದಿ (pglob->gl_pathv != ರಿಕ್ತ) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		ಪ್ರತಿ (i = pglob->gl_pathc; i--; ++pp)
			ಮುಕ್ತ(*pp);
		ಮುಕ್ತ(pglob->gl_pathv);
		pglob->gl_pathv = ರಿಕ್ತ;
	}
	ಯದಿ (pglob->gl_statv != ರಿಕ್ತ) {
		ಪ್ರತಿ (i = 0; i < pglob->gl_pathc; i++) {
			ಮುಕ್ತ(pglob->gl_statv[i]);
		}
		ಮುಕ್ತ(pglob->gl_statv);
		pglob->gl_statv = ರಿಕ್ತ;
	}
}

ಸ್ಥಿರ DIR *
g_opendir(Char *str, glob_t *pglob)
{
	ವರ್ಣ buf[PATH_MAX];

	ಯದಿ (!*str)
		strlcpy(buf, ".", ಪರಿಮಾಣ buf);
	ಅನ್ಯಥಾ {
		ಯದಿ (g_Ctoc(str, buf, ಪರಿಮಾಣ(buf)))
			ಪ್ರತ್ಯಾಗಮ(ರಿಕ್ತ);
	}

	ಯದಿ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ಪ್ರತ್ಯಾಗಮ((*pglob->gl_opendir)(buf));

	ಪ್ರತ್ಯಾಗಮ(opendir(buf));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
g_lstat(Char *fn, ಸಂರಚನಾ stat *sb, glob_t *pglob)
{
	ವರ್ಣ buf[PATH_MAX];

	ಯದಿ (g_Ctoc(fn, buf, ಪರಿಮಾಣ(buf)))
		ಪ್ರತ್ಯಾಗಮ(-1);
	ಯದಿ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ಪ್ರತ್ಯಾಗಮ((*pglob->gl_lstat)(buf, sb));
	ಪ್ರತ್ಯಾಗಮ(lstat(buf, sb));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
g_stat(Char *fn, ಸಂರಚನಾ stat *sb, glob_t *pglob)
{
	ವರ್ಣ buf[PATH_MAX];

	ಯದಿ (g_Ctoc(fn, buf, ಪರಿಮಾಣ(buf)))
		ಪ್ರತ್ಯಾಗಮ(-1);
	ಯದಿ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ಪ್ರತ್ಯಾಗಮ((*pglob->gl_stat)(buf, sb));
	ಪ್ರತ್ಯಾಗಮ(stat(buf, sb));
}

ಸ್ಥಿರ Char *
g_strchr(ಧ್ರುವ Char *str, ಪೂರ್ಣಾಙ್ಕ ch)
{
	ಕುರು {
		ಯದಿ (*str == ch)
			ಪ್ರತ್ಯಾಗಮ ((Char *)str);
	} ಯಾವತ್ (*str++);
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
g_Ctoc(ಧ್ರುವ Char *str, ವರ್ಣ *buf, size_t len)
{

	ಯಾವತ್ (len--) {
		ಯದಿ ((*buf++ = *str++) == EOS)
			ಪ್ರತ್ಯಾಗಮ (0);
	}
	ಪ್ರತ್ಯಾಗಮ (1);
}

#ifdef DEBUG
ಸ್ಥಿರ ಶೂನ್ಯ
qprintf(ಧ್ರುವ ವರ್ಣ *str, Char *s)
{
	Char *p;

	(ಶೂನ್ಯ)printf("%s:\n", str);
	ಪ್ರತಿ (p = s; *p; p++)
		(ಶೂನ್ಯ)printf("%c", CHAR(*p));
	(ಶೂನ್ಯ)printf("\n");
	ಪ್ರತಿ (p = s; *p; p++)
		(ಶೂನ್ಯ)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(ಶೂನ್ಯ)printf("\n");
	ಪ್ರತಿ (p = s; *p; p++)
		(ಶೂನ್ಯ)printf("%c", ismeta(*p) ? '_' : ' ');
	(ಶೂನ್ಯ)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
