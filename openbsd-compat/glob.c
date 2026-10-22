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

#အကယ်၍ !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
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

#မဟုတ်ပါက

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

static ကိန်းပြည့်	 compare(const void *, const void *);
static ကိန်းပြည့်	 compare_gps(const void *, const void *);
static ကိန်းပြည့်	 g_Ctoc(const Char *, var_na *, size_t);
static ကိန်းပြည့်	 g_lstat(Char *, sa_nracanaa stat *, glob_t *);
static DIR	*g_opendir(Char *, glob_t *);
static Char	*g_strchr(const Char *, ကိန်းပြည့်);
static ကိန်းပြည့်	 g_strncmp(const Char *, const var_na *, size_t);
static ကိန်းပြည့်	 g_stat(Char *, sa_nracanaa stat *, glob_t *);
static ကိန်းပြည့်	 glob0(const Char *, glob_t *, sa_nracanaa glob_lim *);
static ကိန်းပြည့်	 glob1(Char *, Char *, glob_t *, sa_nracanaa glob_lim *);
static ကိန်းပြည့်	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, sa_nracanaa glob_lim *);
static ကိန်းပြည့်	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, sa_nracanaa glob_lim *);
static ကိန်းပြည့်	 globextend(const Char *, glob_t *, sa_nracanaa glob_lim *,
		    sa_nracanaa stat *);
static const Char *
		 globtilde(const Char *, Char *, size_t, glob_t *);
static ကိန်းပြည့်	 globexp1(const Char *, glob_t *, sa_nracanaa glob_lim *);
static ကိန်းပြည့်	 globexp2(const Char *, const Char *, glob_t *,
		    sa_nracanaa glob_lim *);
static ကိန်းပြည့်	 match(Char *, Char *, Char *);
#ifdef DEBUG
static void	 qprintf(const var_na *, Char *);
#endif

ကိန်းပြည့်
glob(const var_na *pattern, ကိန်းပြည့် flags, ကိန်းပြည့် (*errfunc)(const var_na *, ကိန်းပြည့်),
    glob_t *pglob)
{
	const u_char *patnext;
	ကိန်းပြည့် c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	sa_nracanaa glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	အကယ်၍ (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = NULL;
		pglob->gl_statv = NULL;
		အကယ်၍ (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	အကယ်၍ (strnlen(pattern, PATH_MAX) == PATH_MAX)
		ပြန်ပေး(GLOB_NOMATCH);

	အကယ်၍ (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		ပြန်ပေး GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	အကယ်၍ (flags & GLOB_NOESCAPE)
		နေစဉ် (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	မဟုတ်ပါက {
		/* Protect the quoted characters. */
		နေစဉ် (bufnext < bufend && (c = *patnext++) != EOS)
			အကယ်၍ (c == QUOTE) {
				အကယ်၍ ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} မဟုတ်ပါက
				*bufnext++ = c;
	}
	*bufnext = EOS;

	အကယ်၍ (flags & GLOB_BRACE)
		ပြန်ပေး globexp1(patbuf, pglob, &limit);
	မဟုတ်ပါက
		ပြန်ပေး glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
static ကိန်းပြည့်
globexp1(const Char *pattern, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	const Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	အကယ်၍ (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		ပြန်ပေး glob0(pattern, pglob, limitp);

	အကယ်၍ ((ptr = (const Char *) g_strchr(ptr, LBRACE)) != NULL)
		ပြန်ပေး globexp2(ptr, pattern, pglob, limitp);

	ပြန်ပေး glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
static ကိန်းပြည့်
globexp2(const Char *ptr, const Char *pattern, glob_t *pglob,
    sa_nracanaa glob_lim *limitp)
{
	ကိန်းပြည့်     i, rv;
	Char   *lm, *ls;
	const Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	အတွက် (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	အတွက် (i = 0, pe = ++ptr; *pe; pe++)
		အကယ်၍ (*pe == LBRACKET) {
			/* Ignore everything between [] */
			အတွက် (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			အကယ်၍ (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} မဟုတ်ပါက အကယ်၍ (*pe == LBRACE)
			i++;
		မဟုတ်ပါက အကယ်၍ (*pe == RBRACE) {
			အကယ်၍ (i == 0)
				bha_nga;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	အကယ်၍ (i != 0 || *pe == EOS)
		ပြန်ပေး glob0(patbuf, pglob, limitp);

	အတွက် (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		switch (*pm) {
		pak_sa LBRACKET:
			/* Ignore everything between [] */
			အတွက် (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			အကယ်၍ (*pm == EOS) {
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
			အကယ်၍ (i) {
				i--;
				bha_nga;
			}
			/* FALLTHROUGH */
		pak_sa COMMA:
			အကယ်၍ (i && *pm == COMMA)
				bha_nga;
			မဟုတ်ပါက {
				/* Append the current string */
				အတွက် (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				အတွက် (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				အကယ်၍ (rv && rv != GLOB_NOMATCH)
					ပြန်ပေး rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			bha_nga;

		default:
			bha_nga;
		}
	}
	ပြန်ပေး 0;
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

	အကယ်၍ (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		ပြန်ပေး pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	အတွက် (p = pattern + 1, h = (var_na *) patbuf;
	    h < (var_na *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#အကယ်၍ 0
	အကယ်၍ (h == (var_na *)eb)
		ပြန်ပေး what;
#endif

	အကယ်၍ (((var_na *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#အကယ်၍ 0
		အကယ်၍ (issetugid() != 0 || (h = getenv("HOME")) == NULL) {
#endif
		အကယ်၍ ((getuid() != geteuid()) || (h = getenv("HOME")) == NULL) {
			အကယ်၍ ((pwd = getpwuid(getuid())) == NULL)
				ပြန်ပေး pattern;
			မဟုတ်ပါက
				h = pwd->pw_dir;
		}
	} မဟုတ်ပါက {
		/*
		 * Expand a ~user
		 */
		အကယ်၍ ((pwd = getpwnam((var_na*) patbuf)) == NULL)
			ပြန်ပေး pattern;
		မဟုတ်ပါက
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	အတွက် (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	နေစဉ် (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	ပြန်ပေး patbuf;
}

static ကိန်းပြည့်
g_strncmp(const Char *s1, const var_na *s2, size_t n)
{
	ကိန်းပြည့် rv = 0;

	နေစဉ် (n--) {
		rv = *(Char *)s1 - *(const unsigned var_na *)s2++;
		အကယ်၍ (rv)
			bha_nga;
		အကယ်၍ (*s1++ == '\0')
			bha_nga;
	}
	ပြန်ပေး rv;
}

static ကိန်းပြည့်
g_charclass(const Char **patternp, Char **bufnextp)
{
	const Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	const Char *colon;
	sa_nracanaa cclass *cc;
	size_t len;

	အကယ်၍ ((colon = g_strchr(pattern, ':')) == NULL || colon[1] != ']')
		ပြန်ပေး 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	အတွက် (cc = cclasses; cc->name != NULL; cc++) {
		အကယ်၍ (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			bha_nga;
	}
	အကယ်၍ (cc->name == NULL)
		ပြန်ပေး -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	ပြန်ပေး 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
static ကိန်းပြည့်
glob0(const Char *pattern, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	const Char *qpatnext;
	ကိန်းပြည့် c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	နေစဉ် ((c = *qpatnext++) != EOS) {
		switch (c) {
		pak_sa LBRACKET:
			c = *qpatnext;
			အကယ်၍ (c == NOT)
				++qpatnext;
			အကယ်၍ (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == NULL) {
				*bufnext++ = LBRACKET;
				အကယ်၍ (c == NOT)
					--qpatnext;
				bha_nga;
			}
			*bufnext++ = M_SET;
			အကယ်၍ (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			do {
				အကယ်၍ (c == LBRACKET && *qpatnext == ':') {
					do {
						err = g_charclass(&qpatnext,
						    &bufnext);
						အကယ်၍ (err)
							bha_nga;
						c = *qpatnext++;
					} နေစဉ် (c == LBRACKET && *qpatnext == ':');
					အကယ်၍ (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						ပြန်ပေး GLOB_NOMATCH;
					အကယ်၍ (c == RBRACKET)
						bha_nga;
				}
				*bufnext++ = CHAR(c);
				အကယ်၍ (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} နေစဉ် ((c = *qpatnext++) != RBRACKET);
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
			အကယ်၍ (bufnext == patbuf || bufnext[-1] != M_ALL)
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

	အကယ်၍ ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		ပြန်ပေး(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	အကယ်၍ (pglob->gl_pathc == oldpathc) {
		အကယ်၍ ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			ပြန်ပေး(globextend(pattern, pglob, limitp, NULL));
		မဟုတ်ပါက
			ပြန်ပေး(GLOB_NOMATCH);
	}
	အကယ်၍ (!(pglob->gl_flags & GLOB_NOSORT)) {
		အကယ်၍ ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			sa_nracanaa glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			အကယ်၍ ((path_stat = calloc(n, parimaa_na(*path_stat))) == NULL)
				ပြန်ပေး GLOB_NOSPACE;
			အတွက် (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, parimaa_na(*path_stat), compare_gps);
			အတွက် (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			free(path_stat);
		} မဟုတ်ပါက {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, parimaa_na(var_na *),
			    compare);
		}
	}
	ပြန်ပေး(0);
}

static ကိန်းပြည့်
compare(const void *p, const void *q)
{
	ပြန်ပေး(strcmp(*(var_na **)p, *(var_na **)q));
}

static ကိန်းပြည့်
compare_gps(const void *_p, const void *_q)
{
	const sa_nracanaa glob_path_stat *p = (const sa_nracanaa glob_path_stat *)_p;
	const sa_nracanaa glob_path_stat *q = (const sa_nracanaa glob_path_stat *)_q;

	ပြန်ပေး(strcmp(p->gps_path, q->gps_path));
}

static ကိန်းပြည့်
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	အကယ်၍ (*pattern == EOS)
		ပြန်ပေး(0);
	ပြန်ပေး(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
static ကိန်းပြည့်
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, sa_nracanaa glob_lim *limitp)
{
	sa_nracanaa stat sb;
	Char *p, *q;
	ကိန်းပြည့် anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	အတွက် (anymeta = 0;;) {
		အကယ်၍ (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			အကယ်၍ ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				ပြန်ပေး(GLOB_NOSPACE);
			}
			အကယ်၍ (g_lstat(pathbuf, &sb, pglob))
				ပြန်ပေး(0);

			အကယ်၍ (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				အကယ်၍ (pathend+1 > pathend_last)
					ပြန်ပေး (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			ပြန်ပေး(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		နေစဉ် (*p != EOS && *p != SEP) {
			အကယ်၍ (ismeta(*p))
				anymeta = 1;
			အကယ်၍ (q+1 > pathend_last)
				ပြန်ပေး (1);
			*q++ = *p++;
		}

		အကယ်၍ (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			နေစဉ် (*pattern == SEP) {
				အကယ်၍ (pathend+1 > pathend_last)
					ပြန်ပေး (1);
				*pathend++ = *pattern++;
			}
		} မဟုတ်ပါက
			/* Need expansion, recurse. */
			ပြန်ပေး(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

static ကိန်းပြည့်
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    sa_nracanaa glob_lim *limitp)
{
	sa_nracanaa dirent *dp;
	DIR *dirp;
	ကိန်းပြည့် err;
	var_na buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	sa_nracanaa dirent *(*readdirfunc)(void *);

	အကယ်၍ (pathend > pathend_last)
		ပြန်ပေး (1);
	*pathend = EOS;
	errno = 0;

	အကယ်၍ ((dirp = g_opendir(pathbuf, pglob)) == NULL) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		အကယ်၍ (pglob->gl_errfunc) {
			အကယ်၍ (g_Ctoc(pathbuf, buf, parimaa_na(buf)))
				ပြန်ပေး(GLOB_ABORTED);
			အကယ်၍ (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				ပြန်ပေး(GLOB_ABORTED);
		}
		ပြန်ပေး(0);
	}

	err = 0;

	/* Search directory for matching names. */
	အကယ်၍ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	မဟုတ်ပါက
		readdirfunc = (sa_nracanaa dirent *(*)(void *))readdir;
	နေစဉ် ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		အကယ်၍ ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			bha_nga;
		}

		/* Initial DOT must be matched literally. */
		အကယ်၍ (dp->d_name[0] == DOT && *pattern != DOT)
			continue;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		နေစဉ် (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		အကယ်၍ (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			bha_nga;
		}

		အကယ်၍ (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			continue;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		အကယ်၍ (err)
			bha_nga;
	}

	အကယ်၍ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	မဟုတ်ပါက
		closedir(dirp);
	ပြန်ပေး(err);
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
static ကိန်းပြည့်
globextend(const Char *path, glob_t *pglob, sa_nracanaa glob_lim *limitp,
    sa_nracanaa stat *sb)
{
	var_na **pathv;
	size_t i, newn, len;
	var_na *copy = NULL;
	const Char *p;
	sa_nracanaa stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	အကယ်၍ (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / parimaa_na(*pathv) <= newn ||
	    SIZE_MAX / parimaa_na(*statv) <= newn) {
 nospace:
		အတွက် (i = pglob->gl_offs; i < newn - 2; i++) {
			အကယ်၍ (pglob->gl_pathv && pglob->gl_pathv[i])
				free(pglob->gl_pathv[i]);
			အကယ်၍ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				free(pglob->gl_statv[i]);
		}
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
		free(pglob->gl_statv);
		pglob->gl_statv = NULL;
		ပြန်ပေး(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, parimaa_na(*pathv));
	အကယ်၍ (pathv == NULL)
		goto nospace;
	အကယ်၍ (pglob->gl_pathv == NULL && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		အတွက် (i = pglob->gl_offs; i > 0; i--)
			*--pathv = NULL;
	}
	pglob->gl_pathv = pathv;

	အကယ်၍ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, parimaa_na(*statv));
		အကယ်၍ (statv == NULL)
			goto nospace;
		အကယ်၍ (pglob->gl_statv == NULL && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			အတွက် (i = pglob->gl_offs; i > 0; i--)
				*--statv = NULL;
		}
		pglob->gl_statv = statv;
		အကယ်၍ (sb == NULL)
			statv[pglob->gl_offs + pglob->gl_pathc] = NULL;
		မဟုတ်ပါက {
			limitp->glim_malloc += parimaa_na(**statv);
			အကယ်၍ ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				ပြန်ပေး(GLOB_NOSPACE);
			}
			အကယ်၍ ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(parimaa_na(**statv))) == NULL)
				goto copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    parimaa_na(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = NULL;
	}

	အတွက် (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	အကယ်၍ ((copy = malloc(len)) != NULL) {
		အကယ်၍ (g_Ctoc(path, copy, len)) {
			free(copy);
			ပြန်ပေး(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;

	အကယ်၍ ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * parimaa_na(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		ပြန်ပေး(GLOB_NOSPACE);
	}
 copy_error:
	ပြန်ပေး(copy == NULL ? GLOB_NOSPACE : 0);
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
static ကိန်းပြည့်
match(Char *name, Char *pat, Char *patend)
{
	ကိန်းပြည့် ok, negate_range;
	Char c, k;
	Char *nextp = NULL;
	Char *nextn = NULL;

loop:
	နေစဉ် (pat < patend) {
		c = *pat++;
		switch (c & M_MASK) {
		pak_sa M_ALL:
			နေစဉ် (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			အကယ်၍ (pat == patend)
				ပြန်ပေး(1);
			အကယ်၍ (*name == EOS)
				ပြန်ပေး(0);
			nextn = name + 1;
			nextp = pat - 1;
			bha_nga;
		pak_sa M_ONE:
			အကယ်၍ (*name++ == EOS)
				goto fail;
			bha_nga;
		pak_sa M_SET:
			ok = 0;
			အကယ်၍ ((k = *name++) == EOS)
				goto fail;
			အကယ်၍ ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			နေစဉ် (((c = *pat++) & M_MASK) != M_END) {
				အကယ်၍ ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					အကယ်၍ (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				အကယ်၍ ((*pat & M_MASK) == M_RNG) {
					အကယ်၍ (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} မဟုတ်ပါက အကယ်၍ (c == k)
					ok = 1;
			}
			အကယ်၍ (ok == negate_range)
				goto fail;
			bha_nga;
		default:
			အကယ်၍ (*name++ != c)
				goto fail;
			bha_nga;
		}
	}
	အကယ်၍ (*name == EOS)
		ပြန်ပေး(1);

fail:
	အကယ်၍ (nextn) {
		pat = nextp;
		name = nextn;
		goto loop;
	}
	ပြန်ပေး(0);
}

/* Free allocated data belonging to a glob_t structure. */
void
globfree(glob_t *pglob)
{
	size_t i;
	var_na **pp;

	အကယ်၍ (pglob->gl_pathv != NULL) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		အတွက် (i = pglob->gl_pathc; i--; ++pp)
			free(*pp);
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
	}
	အကယ်၍ (pglob->gl_statv != NULL) {
		အတွက် (i = 0; i < pglob->gl_pathc; i++) {
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

	အကယ်၍ (!*str)
		strlcpy(buf, ".", parimaa_na buf);
	မဟုတ်ပါက {
		အကယ်၍ (g_Ctoc(str, buf, parimaa_na(buf)))
			ပြန်ပေး(NULL);
	}

	အကယ်၍ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ပြန်ပေး((*pglob->gl_opendir)(buf));

	ပြန်ပေး(opendir(buf));
}

static ကိန်းပြည့်
g_lstat(Char *fn, sa_nracanaa stat *sb, glob_t *pglob)
{
	var_na buf[PATH_MAX];

	အကယ်၍ (g_Ctoc(fn, buf, parimaa_na(buf)))
		ပြန်ပေး(-1);
	အကယ်၍ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ပြန်ပေး((*pglob->gl_lstat)(buf, sb));
	ပြန်ပေး(lstat(buf, sb));
}

static ကိန်းပြည့်
g_stat(Char *fn, sa_nracanaa stat *sb, glob_t *pglob)
{
	var_na buf[PATH_MAX];

	အကယ်၍ (g_Ctoc(fn, buf, parimaa_na(buf)))
		ပြန်ပေး(-1);
	အကယ်၍ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ပြန်ပေး((*pglob->gl_stat)(buf, sb));
	ပြန်ပေး(stat(buf, sb));
}

static Char *
g_strchr(const Char *str, ကိန်းပြည့် ch)
{
	do {
		အကယ်၍ (*str == ch)
			ပြန်ပေး ((Char *)str);
	} နေစဉ် (*str++);
	ပြန်ပေး (NULL);
}

static ကိန်းပြည့်
g_Ctoc(const Char *str, var_na *buf, size_t len)
{

	နေစဉ် (len--) {
		အကယ်၍ ((*buf++ = *str++) == EOS)
			ပြန်ပေး (0);
	}
	ပြန်ပေး (1);
}

#ifdef DEBUG
static void
qprintf(const var_na *str, Char *s)
{
	Char *p;

	(void)printf("%s:\n", str);
	အတွက် (p = s; *p; p++)
		(void)printf("%c", CHAR(*p));
	(void)printf("\n");
	အတွက် (p = s; *p; p++)
		(void)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(void)printf("\n");
	အတွက် (p = s; *p; p++)
		(void)printf("%c", ismeta(*p) ? '_' : ' ');
	(void)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
