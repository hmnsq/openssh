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

#གལ་ཏེ !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
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

#དེ་མིན

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

static ཧྲིལ	 compare(const void *, const void *);
static ཧྲིལ	 compare_gps(const void *, const void *);
static ཧྲིལ	 g_Ctoc(const Char *, var_na *, size_t);
static ཧྲིལ	 g_lstat(Char *, sa_nracanaa stat *, glob_t *);
static DIR	*g_opendir(Char *, glob_t *);
static Char	*g_strchr(const Char *, ཧྲིལ);
static ཧྲིལ	 g_strncmp(const Char *, const var_na *, size_t);
static ཧྲིལ	 g_stat(Char *, sa_nracanaa stat *, glob_t *);
static ཧྲིལ	 glob0(const Char *, glob_t *, sa_nracanaa glob_lim *);
static ཧྲིལ	 glob1(Char *, Char *, glob_t *, sa_nracanaa glob_lim *);
static ཧྲིལ	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, sa_nracanaa glob_lim *);
static ཧྲིལ	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, sa_nracanaa glob_lim *);
static ཧྲིལ	 globextend(const Char *, glob_t *, sa_nracanaa glob_lim *,
		    sa_nracanaa stat *);
static const Char *
		 globtilde(const Char *, Char *, size_t, glob_t *);
static ཧྲིལ	 globexp1(const Char *, glob_t *, sa_nracanaa glob_lim *);
static ཧྲིལ	 globexp2(const Char *, const Char *, glob_t *,
		    sa_nracanaa glob_lim *);
static ཧྲིལ	 match(Char *, Char *, Char *);
#ifdef DEBUG
static void	 qprintf(const var_na *, Char *);
#endif

ཧྲིལ
glob(const var_na *pattern, ཧྲིལ flags, ཧྲིལ (*errfunc)(const var_na *, ཧྲིལ),
    glob_t *pglob)
{
	const u_char *patnext;
	ཧྲིལ c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	sa_nracanaa glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	གལ་ཏེ (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = NULL;
		pglob->gl_statv = NULL;
		གལ་ཏེ (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	གལ་ཏེ (strnlen(pattern, PATH_MAX) == PATH_MAX)
		ཕྱིར(GLOB_NOMATCH);

	གལ་ཏེ (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		ཕྱིར GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	གལ་ཏེ (flags & GLOB_NOESCAPE)
		སྐབས (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	དེ་མིན {
		/* Protect the quoted characters. */
		སྐབས (bufnext < bufend && (c = *patnext++) != EOS)
			གལ་ཏེ (c == QUOTE) {
				གལ་ཏེ ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} དེ་མིན
				*bufnext++ = c;
	}
	*bufnext = EOS;

	གལ་ཏེ (flags & GLOB_BRACE)
		ཕྱིར globexp1(patbuf, pglob, &limit);
	དེ་མིན
		ཕྱིར glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
static ཧྲིལ
globexp1(const Char *pattern, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	const Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	གལ་ཏེ (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		ཕྱིར glob0(pattern, pglob, limitp);

	གལ་ཏེ ((ptr = (const Char *) g_strchr(ptr, LBRACE)) != NULL)
		ཕྱིར globexp2(ptr, pattern, pglob, limitp);

	ཕྱིར glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
static ཧྲིལ
globexp2(const Char *ptr, const Char *pattern, glob_t *pglob,
    sa_nracanaa glob_lim *limitp)
{
	ཧྲིལ     i, rv;
	Char   *lm, *ls;
	const Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	ཆེད་དུ (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	ཆེད་དུ (i = 0, pe = ++ptr; *pe; pe++)
		གལ་ཏེ (*pe == LBRACKET) {
			/* Ignore everything between [] */
			ཆེད་དུ (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			གལ་ཏེ (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} དེ་མིན གལ་ཏེ (*pe == LBRACE)
			i++;
		དེ་མིན གལ་ཏེ (*pe == RBRACE) {
			གལ་ཏེ (i == 0)
				bha_nga;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	གལ་ཏེ (i != 0 || *pe == EOS)
		ཕྱིར glob0(patbuf, pglob, limitp);

	ཆེད་དུ (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		switch (*pm) {
		pak_sa LBRACKET:
			/* Ignore everything between [] */
			ཆེད་དུ (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			གལ་ཏེ (*pm == EOS) {
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
			གལ་ཏེ (i) {
				i--;
				bha_nga;
			}
			/* FALLTHROUGH */
		pak_sa COMMA:
			གལ་ཏེ (i && *pm == COMMA)
				bha_nga;
			དེ་མིན {
				/* Append the current string */
				ཆེད་དུ (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				ཆེད་དུ (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				གལ་ཏེ (rv && rv != GLOB_NOMATCH)
					ཕྱིར rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			bha_nga;

		default:
			bha_nga;
		}
	}
	ཕྱིར 0;
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

	གལ་ཏེ (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		ཕྱིར pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	ཆེད་དུ (p = pattern + 1, h = (var_na *) patbuf;
	    h < (var_na *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#གལ་ཏེ 0
	གལ་ཏེ (h == (var_na *)eb)
		ཕྱིར what;
#endif

	གལ་ཏེ (((var_na *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#གལ་ཏེ 0
		གལ་ཏེ (issetugid() != 0 || (h = getenv("HOME")) == NULL) {
#endif
		གལ་ཏེ ((getuid() != geteuid()) || (h = getenv("HOME")) == NULL) {
			གལ་ཏེ ((pwd = getpwuid(getuid())) == NULL)
				ཕྱིར pattern;
			དེ་མིན
				h = pwd->pw_dir;
		}
	} དེ་མིན {
		/*
		 * Expand a ~user
		 */
		གལ་ཏེ ((pwd = getpwnam((var_na*) patbuf)) == NULL)
			ཕྱིར pattern;
		དེ་མིན
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	ཆེད་དུ (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	སྐབས (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	ཕྱིར patbuf;
}

static ཧྲིལ
g_strncmp(const Char *s1, const var_na *s2, size_t n)
{
	ཧྲིལ rv = 0;

	སྐབས (n--) {
		rv = *(Char *)s1 - *(const unsigned var_na *)s2++;
		གལ་ཏེ (rv)
			bha_nga;
		གལ་ཏེ (*s1++ == '\0')
			bha_nga;
	}
	ཕྱིར rv;
}

static ཧྲིལ
g_charclass(const Char **patternp, Char **bufnextp)
{
	const Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	const Char *colon;
	sa_nracanaa cclass *cc;
	size_t len;

	གལ་ཏེ ((colon = g_strchr(pattern, ':')) == NULL || colon[1] != ']')
		ཕྱིར 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	ཆེད་དུ (cc = cclasses; cc->name != NULL; cc++) {
		གལ་ཏེ (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			bha_nga;
	}
	གལ་ཏེ (cc->name == NULL)
		ཕྱིར -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	ཕྱིར 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
static ཧྲིལ
glob0(const Char *pattern, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	const Char *qpatnext;
	ཧྲིལ c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	སྐབས ((c = *qpatnext++) != EOS) {
		switch (c) {
		pak_sa LBRACKET:
			c = *qpatnext;
			གལ་ཏེ (c == NOT)
				++qpatnext;
			གལ་ཏེ (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == NULL) {
				*bufnext++ = LBRACKET;
				གལ་ཏེ (c == NOT)
					--qpatnext;
				bha_nga;
			}
			*bufnext++ = M_SET;
			གལ་ཏེ (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			do {
				གལ་ཏེ (c == LBRACKET && *qpatnext == ':') {
					do {
						err = g_charclass(&qpatnext,
						    &bufnext);
						གལ་ཏེ (err)
							bha_nga;
						c = *qpatnext++;
					} སྐབས (c == LBRACKET && *qpatnext == ':');
					གལ་ཏེ (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						ཕྱིར GLOB_NOMATCH;
					གལ་ཏེ (c == RBRACKET)
						bha_nga;
				}
				*bufnext++ = CHAR(c);
				གལ་ཏེ (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} སྐབས ((c = *qpatnext++) != RBRACKET);
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
			གལ་ཏེ (bufnext == patbuf || bufnext[-1] != M_ALL)
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

	གལ་ཏེ ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		ཕྱིར(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	གལ་ཏེ (pglob->gl_pathc == oldpathc) {
		གལ་ཏེ ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			ཕྱིར(globextend(pattern, pglob, limitp, NULL));
		དེ་མིན
			ཕྱིར(GLOB_NOMATCH);
	}
	གལ་ཏེ (!(pglob->gl_flags & GLOB_NOSORT)) {
		གལ་ཏེ ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			sa_nracanaa glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			གལ་ཏེ ((path_stat = calloc(n, parimaa_na(*path_stat))) == NULL)
				ཕྱིར GLOB_NOSPACE;
			ཆེད་དུ (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, parimaa_na(*path_stat), compare_gps);
			ཆེད་དུ (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			free(path_stat);
		} དེ་མིན {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, parimaa_na(var_na *),
			    compare);
		}
	}
	ཕྱིར(0);
}

static ཧྲིལ
compare(const void *p, const void *q)
{
	ཕྱིར(strcmp(*(var_na **)p, *(var_na **)q));
}

static ཧྲིལ
compare_gps(const void *_p, const void *_q)
{
	const sa_nracanaa glob_path_stat *p = (const sa_nracanaa glob_path_stat *)_p;
	const sa_nracanaa glob_path_stat *q = (const sa_nracanaa glob_path_stat *)_q;

	ཕྱིར(strcmp(p->gps_path, q->gps_path));
}

static ཧྲིལ
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	གལ་ཏེ (*pattern == EOS)
		ཕྱིར(0);
	ཕྱིར(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
static ཧྲིལ
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	sa_nracanaa stat sb;
	Char *p, *q;
	ཧྲིལ anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	ཆེད་དུ (anymeta = 0;;) {
		གལ་ཏེ (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			གལ་ཏེ ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				ཕྱིར(GLOB_NOSPACE);
			}
			གལ་ཏེ (g_lstat(pathbuf, &sb, pglob))
				ཕྱིར(0);

			གལ་ཏེ (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				གལ་ཏེ (pathend+1 > pathend_last)
					ཕྱིར (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			ཕྱིར(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		སྐབས (*p != EOS && *p != SEP) {
			གལ་ཏེ (ismeta(*p))
				anymeta = 1;
			གལ་ཏེ (q+1 > pathend_last)
				ཕྱིར (1);
			*q++ = *p++;
		}

		གལ་ཏེ (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			སྐབས (*pattern == SEP) {
				གལ་ཏེ (pathend+1 > pathend_last)
					ཕྱིར (1);
				*pathend++ = *pattern++;
			}
		} དེ་མིན
			/* Need expansion, recurse. */
			ཕྱིར(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

static ཧྲིལ
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    sa_nracanaa glob_lim *limitp)
{
	sa_nracanaa dirent *dp;
	DIR *dirp;
	ཧྲིལ err;
	var_na buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	sa_nracanaa dirent *(*readdirfunc)(void *);

	གལ་ཏེ (pathend > pathend_last)
		ཕྱིར (1);
	*pathend = EOS;
	errno = 0;

	གལ་ཏེ ((dirp = g_opendir(pathbuf, pglob)) == NULL) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		གལ་ཏེ (pglob->gl_errfunc) {
			གལ་ཏེ (g_Ctoc(pathbuf, buf, parimaa_na(buf)))
				ཕྱིར(GLOB_ABORTED);
			གལ་ཏེ (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				ཕྱིར(GLOB_ABORTED);
		}
		ཕྱིར(0);
	}

	err = 0;

	/* Search directory for matching names. */
	གལ་ཏེ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	དེ་མིན
		readdirfunc = (sa_nracanaa dirent *(*)(void *))readdir;
	སྐབས ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		གལ་ཏེ ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			bha_nga;
		}

		/* Initial DOT must be matched literally. */
		གལ་ཏེ (dp->d_name[0] == DOT && *pattern != DOT)
			continue;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		སྐབས (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		གལ་ཏེ (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			bha_nga;
		}

		གལ་ཏེ (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			continue;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		གལ་ཏེ (err)
			bha_nga;
	}

	གལ་ཏེ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	དེ་མིན
		closedir(dirp);
	ཕྱིར(err);
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
static ཧྲིལ
globextend(const Char *path, glob_t *pglob, sa_nracanaa glob_lim *limitp,
    sa_nracanaa stat *sb)
{
	var_na **pathv;
	size_t i, newn, len;
	var_na *copy = NULL;
	const Char *p;
	sa_nracanaa stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	གལ་ཏེ (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / parimaa_na(*pathv) <= newn ||
	    SIZE_MAX / parimaa_na(*statv) <= newn) {
 nospace:
		ཆེད་དུ (i = pglob->gl_offs; i < newn - 2; i++) {
			གལ་ཏེ (pglob->gl_pathv && pglob->gl_pathv[i])
				free(pglob->gl_pathv[i]);
			གལ་ཏེ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				free(pglob->gl_statv[i]);
		}
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
		free(pglob->gl_statv);
		pglob->gl_statv = NULL;
		ཕྱིར(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, parimaa_na(*pathv));
	གལ་ཏེ (pathv == NULL)
		goto nospace;
	གལ་ཏེ (pglob->gl_pathv == NULL && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		ཆེད་དུ (i = pglob->gl_offs; i > 0; i--)
			*--pathv = NULL;
	}
	pglob->gl_pathv = pathv;

	གལ་ཏེ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, parimaa_na(*statv));
		གལ་ཏེ (statv == NULL)
			goto nospace;
		གལ་ཏེ (pglob->gl_statv == NULL && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			ཆེད་དུ (i = pglob->gl_offs; i > 0; i--)
				*--statv = NULL;
		}
		pglob->gl_statv = statv;
		གལ་ཏེ (sb == NULL)
			statv[pglob->gl_offs + pglob->gl_pathc] = NULL;
		དེ་མིན {
			limitp->glim_malloc += parimaa_na(**statv);
			གལ་ཏེ ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				ཕྱིར(GLOB_NOSPACE);
			}
			གལ་ཏེ ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(parimaa_na(**statv))) == NULL)
				goto copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    parimaa_na(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = NULL;
	}

	ཆེད་དུ (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	གལ་ཏེ ((copy = malloc(len)) != NULL) {
		གལ་ཏེ (g_Ctoc(path, copy, len)) {
			free(copy);
			ཕྱིར(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;

	གལ་ཏེ ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * parimaa_na(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		ཕྱིར(GLOB_NOSPACE);
	}
 copy_error:
	ཕྱིར(copy == NULL ? GLOB_NOSPACE : 0);
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
static ཧྲིལ
match(Char *name, Char *pat, Char *patend)
{
	ཧྲིལ ok, negate_range;
	Char c, k;
	Char *nextp = NULL;
	Char *nextn = NULL;

loop:
	སྐབས (pat < patend) {
		c = *pat++;
		switch (c & M_MASK) {
		pak_sa M_ALL:
			སྐབས (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			གལ་ཏེ (pat == patend)
				ཕྱིར(1);
			གལ་ཏེ (*name == EOS)
				ཕྱིར(0);
			nextn = name + 1;
			nextp = pat - 1;
			bha_nga;
		pak_sa M_ONE:
			གལ་ཏེ (*name++ == EOS)
				goto fail;
			bha_nga;
		pak_sa M_SET:
			ok = 0;
			གལ་ཏེ ((k = *name++) == EOS)
				goto fail;
			གལ་ཏེ ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			སྐབས (((c = *pat++) & M_MASK) != M_END) {
				གལ་ཏེ ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					གལ་ཏེ (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				གལ་ཏེ ((*pat & M_MASK) == M_RNG) {
					གལ་ཏེ (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} དེ་མིན གལ་ཏེ (c == k)
					ok = 1;
			}
			གལ་ཏེ (ok == negate_range)
				goto fail;
			bha_nga;
		default:
			གལ་ཏེ (*name++ != c)
				goto fail;
			bha_nga;
		}
	}
	གལ་ཏེ (*name == EOS)
		ཕྱིར(1);

fail:
	གལ་ཏེ (nextn) {
		pat = nextp;
		name = nextn;
		goto loop;
	}
	ཕྱིར(0);
}

/* Free allocated data belonging to a glob_t structure. */
void
globfree(glob_t *pglob)
{
	size_t i;
	var_na **pp;

	གལ་ཏེ (pglob->gl_pathv != NULL) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		ཆེད་དུ (i = pglob->gl_pathc; i--; ++pp)
			free(*pp);
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
	}
	གལ་ཏེ (pglob->gl_statv != NULL) {
		ཆེད་དུ (i = 0; i < pglob->gl_pathc; i++) {
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

	གལ་ཏེ (!*str)
		strlcpy(buf, ".", parimaa_na buf);
	དེ་མིན {
		གལ་ཏེ (g_Ctoc(str, buf, parimaa_na(buf)))
			ཕྱིར(NULL);
	}

	གལ་ཏེ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ཕྱིར((*pglob->gl_opendir)(buf));

	ཕྱིར(opendir(buf));
}

static ཧྲིལ
g_lstat(Char *fn, sa_nracanaa stat *sb, glob_t *pglob)
{
	var_na buf[PATH_MAX];

	གལ་ཏེ (g_Ctoc(fn, buf, parimaa_na(buf)))
		ཕྱིར(-1);
	གལ་ཏེ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ཕྱིར((*pglob->gl_lstat)(buf, sb));
	ཕྱིར(lstat(buf, sb));
}

static ཧྲིལ
g_stat(Char *fn, sa_nracanaa stat *sb, glob_t *pglob)
{
	var_na buf[PATH_MAX];

	གལ་ཏེ (g_Ctoc(fn, buf, parimaa_na(buf)))
		ཕྱིར(-1);
	གལ་ཏེ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ཕྱིར((*pglob->gl_stat)(buf, sb));
	ཕྱིར(stat(buf, sb));
}

static Char *
g_strchr(const Char *str, ཧྲིལ ch)
{
	do {
		གལ་ཏེ (*str == ch)
			ཕྱིར ((Char *)str);
	} སྐབས (*str++);
	ཕྱིར (NULL);
}

static ཧྲིལ
g_Ctoc(const Char *str, var_na *buf, size_t len)
{

	སྐབས (len--) {
		གལ་ཏེ ((*buf++ = *str++) == EOS)
			ཕྱིར (0);
	}
	ཕྱིར (1);
}

#ifdef DEBUG
static void
qprintf(const var_na *str, Char *s)
{
	Char *p;

	(void)printf("%s:\n", str);
	ཆེད་དུ (p = s; *p; p++)
		(void)printf("%c", CHAR(*p));
	(void)printf("\n");
	ཆེད་དུ (p = s; *p; p++)
		(void)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(void)printf("\n");
	ཆེད་དུ (p = s; *p; p++)
		(void)printf("%c", ismeta(*p) ? '_' : ' ');
	(void)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
