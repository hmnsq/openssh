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

#include "includes.h"
#include "glob.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ᯀᯮᯝ !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#include "charclass.h"

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

typedef u_short Char;

#ᯀᯮᯝᯂᯪ

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

typedef var_na Char;

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

sa_nracanaa glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

sa_nracanaa glob_path_stat {
	var_na		*gps_path;
	sa_nracanaa stat	*gps_stat;
};

static puur_naa_nka	 compare(const void *, const void *);
static puur_naa_nka	 compare_gps(const void *, const void *);
static puur_naa_nka	 g_Ctoc(const Char *, var_na *, size_t);
static puur_naa_nka	 g_lstat(Char *, sa_nracanaa stat *, glob_t *);
static DIR	*g_opendir(Char *, glob_t *);
static Char	*g_strchr(const Char *, puur_naa_nka);
static puur_naa_nka	 g_strncmp(const Char *, const var_na *, size_t);
static puur_naa_nka	 g_stat(Char *, sa_nracanaa stat *, glob_t *);
static puur_naa_nka	 glob0(const Char *, glob_t *, sa_nracanaa glob_lim *);
static puur_naa_nka	 glob1(Char *, Char *, glob_t *, sa_nracanaa glob_lim *);
static puur_naa_nka	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, sa_nracanaa glob_lim *);
static puur_naa_nka	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, sa_nracanaa glob_lim *);
static puur_naa_nka	 globextend(const Char *, glob_t *, sa_nracanaa glob_lim *,
		    sa_nracanaa stat *);
static const Char *
		 globtilde(const Char *, Char *, size_t, glob_t *);
static puur_naa_nka	 globexp1(const Char *, glob_t *, sa_nracanaa glob_lim *);
static puur_naa_nka	 globexp2(const Char *, const Char *, glob_t *,
		    sa_nracanaa glob_lim *);
static puur_naa_nka	 match(Char *, Char *, Char *);
#ifdef DEBUG
static void	 qprintf(const var_na *, Char *);
#endif

puur_naa_nka
glob(const var_na *pattern, puur_naa_nka flags, puur_naa_nka (*errfunc)(const var_na *, puur_naa_nka),
    glob_t *pglob)
{
	const u_char *patnext;
	puur_naa_nka c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	sa_nracanaa glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	ᯀᯮᯝ (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = NULL;
		pglob->gl_statv = NULL;
		ᯀᯮᯝ (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	ᯀᯮᯝ (strnlen(pattern, PATH_MAX) == PATH_MAX)
		ᯀᯮᯞ(GLOB_NOMATCH);

	ᯀᯮᯝ (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		ᯀᯮᯞ GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	ᯀᯮᯝ (flags & GLOB_NOESCAPE)
		ᯀᯬᯝ (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	ᯀᯮᯝᯂᯪ {
		/* Protect the quoted characters. */
		ᯀᯬᯝ (bufnext < bufend && (c = *patnext++) != EOS)
			ᯀᯮᯝ (c == QUOTE) {
				ᯀᯮᯝ ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} ᯀᯮᯝᯂᯪ
				*bufnext++ = c;
	}
	*bufnext = EOS;

	ᯀᯮᯝ (flags & GLOB_BRACE)
		ᯀᯮᯞ globexp1(patbuf, pglob, &limit);
	ᯀᯮᯝᯂᯪ
		ᯀᯮᯞ glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
static puur_naa_nka
globexp1(const Char *pattern, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	const Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	ᯀᯮᯝ (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		ᯀᯮᯞ glob0(pattern, pglob, limitp);

	ᯀᯮᯝ ((ptr = (const Char *) g_strchr(ptr, LBRACE)) != NULL)
		ᯀᯮᯞ globexp2(ptr, pattern, pglob, limitp);

	ᯀᯮᯞ glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
static puur_naa_nka
globexp2(const Char *ptr, const Char *pattern, glob_t *pglob,
    sa_nracanaa glob_lim *limitp)
{
	puur_naa_nka     i, rv;
	Char   *lm, *ls;
	const Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	for (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	for (i = 0, pe = ++ptr; *pe; pe++)
		ᯀᯮᯝ (*pe == LBRACKET) {
			/* Ignore everything between [] */
			for (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			ᯀᯮᯝ (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} ᯀᯮᯝᯂᯪ ᯀᯮᯝ (*pe == LBRACE)
			i++;
		ᯀᯮᯝᯂᯪ ᯀᯮᯝ (*pe == RBRACE) {
			ᯀᯮᯝ (i == 0)
				bha_nga;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	ᯀᯮᯝ (i != 0 || *pe == EOS)
		ᯀᯮᯞ glob0(patbuf, pglob, limitp);

	for (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		switch (*pm) {
		pak_sa LBRACKET:
			/* Ignore everything between [] */
			for (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			ᯀᯮᯝ (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			bha_nga;

		pak_sa LBRACE:
			i++;
			bha_nga;

		pak_sa RBRACE:
			ᯀᯮᯝ (i) {
				i--;
				bha_nga;
			}
			/* FALLTHROUGH */
		pak_sa COMMA:
			ᯀᯮᯝ (i && *pm == COMMA)
				bha_nga;
			ᯀᯮᯝᯂᯪ {
				/* Append the current string */
				for (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				for (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				ᯀᯮᯝ (rv && rv != GLOB_NOMATCH)
					ᯀᯮᯞ rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			bha_nga;

		default:
			bha_nga;
		}
	}
	ᯀᯮᯞ 0;
}



/*
 * expand tilde from the passwd file.
 */
static const Char *
globtilde(const Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	sa_nracanaa passwd *pwd;
	var_na *h;
	const Char *p;
	Char *b, *eb;

	ᯀᯮᯝ (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		ᯀᯮᯞ pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	for (p = pattern + 1, h = (var_na *) patbuf;
	    h < (var_na *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#ᯀᯮᯝ 0
	ᯀᯮᯝ (h == (var_na *)eb)
		ᯀᯮᯞ what;
#endif

	ᯀᯮᯝ (((var_na *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#ᯀᯮᯝ 0
		ᯀᯮᯝ (issetugid() != 0 || (h = getenv("HOME")) == NULL) {
#endif
		ᯀᯮᯝ ((getuid() != geteuid()) || (h = getenv("HOME")) == NULL) {
			ᯀᯮᯝ ((pwd = getpwuid(getuid())) == NULL)
				ᯀᯮᯞ pattern;
			ᯀᯮᯝᯂᯪ
				h = pwd->pw_dir;
		}
	} ᯀᯮᯝᯂᯪ {
		/*
		 * Expand a ~user
		 */
		ᯀᯮᯝ ((pwd = getpwnam((var_na*) patbuf)) == NULL)
			ᯀᯮᯞ pattern;
		ᯀᯮᯝᯂᯪ
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	for (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	ᯀᯬᯝ (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	ᯀᯮᯞ patbuf;
}

static puur_naa_nka
g_strncmp(const Char *s1, const var_na *s2, size_t n)
{
	puur_naa_nka rv = 0;

	ᯀᯬᯝ (n--) {
		rv = *(Char *)s1 - *(const unsigned var_na *)s2++;
		ᯀᯮᯝ (rv)
			bha_nga;
		ᯀᯮᯝ (*s1++ == '\0')
			bha_nga;
	}
	ᯀᯮᯞ rv;
}

static puur_naa_nka
g_charclass(const Char **patternp, Char **bufnextp)
{
	const Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	const Char *colon;
	sa_nracanaa cclass *cc;
	size_t len;

	ᯀᯮᯝ ((colon = g_strchr(pattern, ':')) == NULL || colon[1] != ']')
		ᯀᯮᯞ 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	for (cc = cclasses; cc->name != NULL; cc++) {
		ᯀᯮᯝ (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			bha_nga;
	}
	ᯀᯮᯝ (cc->name == NULL)
		ᯀᯮᯞ -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	ᯀᯮᯞ 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
static puur_naa_nka
glob0(const Char *pattern, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	const Char *qpatnext;
	puur_naa_nka c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	ᯀᯬᯝ ((c = *qpatnext++) != EOS) {
		switch (c) {
		pak_sa LBRACKET:
			c = *qpatnext;
			ᯀᯮᯝ (c == NOT)
				++qpatnext;
			ᯀᯮᯝ (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == NULL) {
				*bufnext++ = LBRACKET;
				ᯀᯮᯝ (c == NOT)
					--qpatnext;
				bha_nga;
			}
			*bufnext++ = M_SET;
			ᯀᯮᯝ (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			do {
				ᯀᯮᯝ (c == LBRACKET && *qpatnext == ':') {
					do {
						err = g_charclass(&qpatnext,
						    &bufnext);
						ᯀᯮᯝ (err)
							bha_nga;
						c = *qpatnext++;
					} ᯀᯬᯝ (c == LBRACKET && *qpatnext == ':');
					ᯀᯮᯝ (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						ᯀᯮᯞ GLOB_NOMATCH;
					ᯀᯮᯝ (c == RBRACKET)
						bha_nga;
				}
				*bufnext++ = CHAR(c);
				ᯀᯮᯝ (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} ᯀᯬᯝ ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			bha_nga;
		pak_sa QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			bha_nga;
		pak_sa STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			ᯀᯮᯝ (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			bha_nga;
		default:
			*bufnext++ = CHAR(c);
			bha_nga;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	ᯀᯮᯝ ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		ᯀᯮᯞ(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	ᯀᯮᯝ (pglob->gl_pathc == oldpathc) {
		ᯀᯮᯝ ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			ᯀᯮᯞ(globextend(pattern, pglob, limitp, NULL));
		ᯀᯮᯝᯂᯪ
			ᯀᯮᯞ(GLOB_NOMATCH);
	}
	ᯀᯮᯝ (!(pglob->gl_flags & GLOB_NOSORT)) {
		ᯀᯮᯝ ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			sa_nracanaa glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			ᯀᯮᯝ ((path_stat = calloc(n, parimaa_na(*path_stat))) == NULL)
				ᯀᯮᯞ GLOB_NOSPACE;
			for (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, parimaa_na(*path_stat), compare_gps);
			for (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			free(path_stat);
		} ᯀᯮᯝᯂᯪ {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, parimaa_na(var_na *),
			    compare);
		}
	}
	ᯀᯮᯞ(0);
}

static puur_naa_nka
compare(const void *p, const void *q)
{
	ᯀᯮᯞ(strcmp(*(var_na **)p, *(var_na **)q));
}

static puur_naa_nka
compare_gps(const void *_p, const void *_q)
{
	const sa_nracanaa glob_path_stat *p = (const sa_nracanaa glob_path_stat *)_p;
	const sa_nracanaa glob_path_stat *q = (const sa_nracanaa glob_path_stat *)_q;

	ᯀᯮᯞ(strcmp(p->gps_path, q->gps_path));
}

static puur_naa_nka
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	ᯀᯮᯝ (*pattern == EOS)
		ᯀᯮᯞ(0);
	ᯀᯮᯞ(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
static puur_naa_nka
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	sa_nracanaa stat sb;
	Char *p, *q;
	puur_naa_nka anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	for (anymeta = 0;;) {
		ᯀᯮᯝ (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			ᯀᯮᯝ ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				ᯀᯮᯞ(GLOB_NOSPACE);
			}
			ᯀᯮᯝ (g_lstat(pathbuf, &sb, pglob))
				ᯀᯮᯞ(0);

			ᯀᯮᯝ (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				ᯀᯮᯝ (pathend+1 > pathend_last)
					ᯀᯮᯞ (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			ᯀᯮᯞ(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		ᯀᯬᯝ (*p != EOS && *p != SEP) {
			ᯀᯮᯝ (ismeta(*p))
				anymeta = 1;
			ᯀᯮᯝ (q+1 > pathend_last)
				ᯀᯮᯞ (1);
			*q++ = *p++;
		}

		ᯀᯮᯝ (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			ᯀᯬᯝ (*pattern == SEP) {
				ᯀᯮᯝ (pathend+1 > pathend_last)
					ᯀᯮᯞ (1);
				*pathend++ = *pattern++;
			}
		} ᯀᯮᯝᯂᯪ
			/* Need expansion, recurse. */
			ᯀᯮᯞ(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

static puur_naa_nka
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    sa_nracanaa glob_lim *limitp)
{
	sa_nracanaa dirent *dp;
	DIR *dirp;
	puur_naa_nka err;
	var_na buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	sa_nracanaa dirent *(*readdirfunc)(void *);

	ᯀᯮᯝ (pathend > pathend_last)
		ᯀᯮᯞ (1);
	*pathend = EOS;
	errno = 0;

	ᯀᯮᯝ ((dirp = g_opendir(pathbuf, pglob)) == NULL) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		ᯀᯮᯝ (pglob->gl_errfunc) {
			ᯀᯮᯝ (g_Ctoc(pathbuf, buf, parimaa_na(buf)))
				ᯀᯮᯞ(GLOB_ABORTED);
			ᯀᯮᯝ (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				ᯀᯮᯞ(GLOB_ABORTED);
		}
		ᯀᯮᯞ(0);
	}

	err = 0;

	/* Search directory for matching names. */
	ᯀᯮᯝ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	ᯀᯮᯝᯂᯪ
		readdirfunc = (sa_nracanaa dirent *(*)(void *))readdir;
	ᯀᯬᯝ ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		ᯀᯮᯝ ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			bha_nga;
		}

		/* Initial DOT must be matched literally. */
		ᯀᯮᯝ (dp->d_name[0] == DOT && *pattern != DOT)
			continue;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		ᯀᯬᯝ (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		ᯀᯮᯝ (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			bha_nga;
		}

		ᯀᯮᯝ (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			continue;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		ᯀᯮᯝ (err)
			bha_nga;
	}

	ᯀᯮᯝ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	ᯀᯮᯝᯂᯪ
		closedir(dirp);
	ᯀᯮᯞ(err);
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
static puur_naa_nka
globextend(const Char *path, glob_t *pglob, sa_nracanaa glob_lim *limitp,
    sa_nracanaa stat *sb)
{
	var_na **pathv;
	size_t i, newn, len;
	var_na *copy = NULL;
	const Char *p;
	sa_nracanaa stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	ᯀᯮᯝ (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / parimaa_na(*pathv) <= newn ||
	    SIZE_MAX / parimaa_na(*statv) <= newn) {
 nospace:
		for (i = pglob->gl_offs; i < newn - 2; i++) {
			ᯀᯮᯝ (pglob->gl_pathv && pglob->gl_pathv[i])
				free(pglob->gl_pathv[i]);
			ᯀᯮᯝ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				free(pglob->gl_statv[i]);
		}
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
		free(pglob->gl_statv);
		pglob->gl_statv = NULL;
		ᯀᯮᯞ(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, parimaa_na(*pathv));
	ᯀᯮᯝ (pathv == NULL)
		goto nospace;
	ᯀᯮᯝ (pglob->gl_pathv == NULL && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		for (i = pglob->gl_offs; i > 0; i--)
			*--pathv = NULL;
	}
	pglob->gl_pathv = pathv;

	ᯀᯮᯝ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, parimaa_na(*statv));
		ᯀᯮᯝ (statv == NULL)
			goto nospace;
		ᯀᯮᯝ (pglob->gl_statv == NULL && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			for (i = pglob->gl_offs; i > 0; i--)
				*--statv = NULL;
		}
		pglob->gl_statv = statv;
		ᯀᯮᯝ (sb == NULL)
			statv[pglob->gl_offs + pglob->gl_pathc] = NULL;
		ᯀᯮᯝᯂᯪ {
			limitp->glim_malloc += parimaa_na(**statv);
			ᯀᯮᯝ ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				ᯀᯮᯞ(GLOB_NOSPACE);
			}
			ᯀᯮᯝ ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(parimaa_na(**statv))) == NULL)
				goto copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    parimaa_na(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = NULL;
	}

	for (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	ᯀᯮᯝ ((copy = malloc(len)) != NULL) {
		ᯀᯮᯝ (g_Ctoc(path, copy, len)) {
			free(copy);
			ᯀᯮᯞ(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;

	ᯀᯮᯝ ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * parimaa_na(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		ᯀᯮᯞ(GLOB_NOSPACE);
	}
 copy_error:
	ᯀᯮᯞ(copy == NULL ? GLOB_NOSPACE : 0);
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
static puur_naa_nka
match(Char *name, Char *pat, Char *patend)
{
	puur_naa_nka ok, negate_range;
	Char c, k;
	Char *nextp = NULL;
	Char *nextn = NULL;

loop:
	ᯀᯬᯝ (pat < patend) {
		c = *pat++;
		switch (c & M_MASK) {
		pak_sa M_ALL:
			ᯀᯬᯝ (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			ᯀᯮᯝ (pat == patend)
				ᯀᯮᯞ(1);
			ᯀᯮᯝ (*name == EOS)
				ᯀᯮᯞ(0);
			nextn = name + 1;
			nextp = pat - 1;
			bha_nga;
		pak_sa M_ONE:
			ᯀᯮᯝ (*name++ == EOS)
				goto fail;
			bha_nga;
		pak_sa M_SET:
			ok = 0;
			ᯀᯮᯝ ((k = *name++) == EOS)
				goto fail;
			ᯀᯮᯝ ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			ᯀᯬᯝ (((c = *pat++) & M_MASK) != M_END) {
				ᯀᯮᯝ ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					ᯀᯮᯝ (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				ᯀᯮᯝ ((*pat & M_MASK) == M_RNG) {
					ᯀᯮᯝ (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} ᯀᯮᯝᯂᯪ ᯀᯮᯝ (c == k)
					ok = 1;
			}
			ᯀᯮᯝ (ok == negate_range)
				goto fail;
			bha_nga;
		default:
			ᯀᯮᯝ (*name++ != c)
				goto fail;
			bha_nga;
		}
	}
	ᯀᯮᯝ (*name == EOS)
		ᯀᯮᯞ(1);

fail:
	ᯀᯮᯝ (nextn) {
		pat = nextp;
		name = nextn;
		goto loop;
	}
	ᯀᯮᯞ(0);
}

/* Free allocated data belonging to a glob_t structure. */
void
globfree(glob_t *pglob)
{
	size_t i;
	var_na **pp;

	ᯀᯮᯝ (pglob->gl_pathv != NULL) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		for (i = pglob->gl_pathc; i--; ++pp)
			free(*pp);
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
	}
	ᯀᯮᯝ (pglob->gl_statv != NULL) {
		for (i = 0; i < pglob->gl_pathc; i++) {
			free(pglob->gl_statv[i]);
		}
		free(pglob->gl_statv);
		pglob->gl_statv = NULL;
	}
}

static DIR *
g_opendir(Char *str, glob_t *pglob)
{
	var_na buf[PATH_MAX];

	ᯀᯮᯝ (!*str)
		strlcpy(buf, ".", parimaa_na buf);
	ᯀᯮᯝᯂᯪ {
		ᯀᯮᯝ (g_Ctoc(str, buf, parimaa_na(buf)))
			ᯀᯮᯞ(NULL);
	}

	ᯀᯮᯝ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ᯀᯮᯞ((*pglob->gl_opendir)(buf));

	ᯀᯮᯞ(opendir(buf));
}

static puur_naa_nka
g_lstat(Char *fn, sa_nracanaa stat *sb, glob_t *pglob)
{
	var_na buf[PATH_MAX];

	ᯀᯮᯝ (g_Ctoc(fn, buf, parimaa_na(buf)))
		ᯀᯮᯞ(-1);
	ᯀᯮᯝ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ᯀᯮᯞ((*pglob->gl_lstat)(buf, sb));
	ᯀᯮᯞ(lstat(buf, sb));
}

static puur_naa_nka
g_stat(Char *fn, sa_nracanaa stat *sb, glob_t *pglob)
{
	var_na buf[PATH_MAX];

	ᯀᯮᯝ (g_Ctoc(fn, buf, parimaa_na(buf)))
		ᯀᯮᯞ(-1);
	ᯀᯮᯝ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ᯀᯮᯞ((*pglob->gl_stat)(buf, sb));
	ᯀᯮᯞ(stat(buf, sb));
}

static Char *
g_strchr(const Char *str, puur_naa_nka ch)
{
	do {
		ᯀᯮᯝ (*str == ch)
			ᯀᯮᯞ ((Char *)str);
	} ᯀᯬᯝ (*str++);
	ᯀᯮᯞ (NULL);
}

static puur_naa_nka
g_Ctoc(const Char *str, var_na *buf, size_t len)
{

	ᯀᯬᯝ (len--) {
		ᯀᯮᯝ ((*buf++ = *str++) == EOS)
			ᯀᯮᯞ (0);
	}
	ᯀᯮᯞ (1);
}

#ifdef DEBUG
static void
qprintf(const var_na *str, Char *s)
{
	Char *p;

	(void)printf("%s:\n", str);
	for (p = s; *p; p++)
		(void)printf("%c", CHAR(*p));
	(void)printf("\n");
	for (p = s; *p; p++)
		(void)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(void)printf("\n");
	for (p = s; *p; p++)
		(void)printf("%c", ismeta(*p) ? '_' : ' ');
	(void)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
