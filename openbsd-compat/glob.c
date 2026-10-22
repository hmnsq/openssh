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

#もし !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
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

#否则

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

typedef char Char;

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

struct glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

struct glob_path_stat {
	char		*gps_path;
	struct stat	*gps_stat;
};

static 整数	 compare(const void *, const void *);
static 整数	 compare_gps(const void *, const void *);
static 整数	 g_Ctoc(const Char *, char *, size_t);
static 整数	 g_lstat(Char *, struct stat *, glob_t *);
static DIR	*g_opendir(Char *, glob_t *);
static Char	*g_strchr(const Char *, 整数);
static 整数	 g_strncmp(const Char *, const char *, size_t);
static 整数	 g_stat(Char *, struct stat *, glob_t *);
static 整数	 glob0(const Char *, glob_t *, struct glob_lim *);
static 整数	 glob1(Char *, Char *, glob_t *, struct glob_lim *);
static 整数	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, struct glob_lim *);
static 整数	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, struct glob_lim *);
static 整数	 globextend(const Char *, glob_t *, struct glob_lim *,
		    struct stat *);
static const Char *
		 globtilde(const Char *, Char *, size_t, glob_t *);
static 整数	 globexp1(const Char *, glob_t *, struct glob_lim *);
static 整数	 globexp2(const Char *, const Char *, glob_t *,
		    struct glob_lim *);
static 整数	 match(Char *, Char *, Char *);
#ifdef DEBUG
static void	 qprintf(const char *, Char *);
#endif

整数
glob(const char *pattern, 整数 flags, 整数 (*errfunc)(const char *, 整数),
    glob_t *pglob)
{
	const u_char *patnext;
	整数 c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	struct glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	もし (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = NULL;
		pglob->gl_statv = NULL;
		もし (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	もし (strnlen(pattern, PATH_MAX) == PATH_MAX)
		戻る(GLOB_NOMATCH);

	もし (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		戻る GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	もし (flags & GLOB_NOESCAPE)
		ながら (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	否则 {
		/* Protect the quoted characters. */
		ながら (bufnext < bufend && (c = *patnext++) != EOS)
			もし (c == QUOTE) {
				もし ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} 否则
				*bufnext++ = c;
	}
	*bufnext = EOS;

	もし (flags & GLOB_BRACE)
		戻る globexp1(patbuf, pglob, &limit);
	否则
		戻る glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
static 整数
globexp1(const Char *pattern, glob_t *pglob, struct glob_lim *limitp)
{
	const Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	もし (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		戻る glob0(pattern, pglob, limitp);

	もし ((ptr = (const Char *) g_strchr(ptr, LBRACE)) != NULL)
		戻る globexp2(ptr, pattern, pglob, limitp);

	戻る glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
static 整数
globexp2(const Char *ptr, const Char *pattern, glob_t *pglob,
    struct glob_lim *limitp)
{
	整数     i, rv;
	Char   *lm, *ls;
	const Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	ために (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	ために (i = 0, pe = ++ptr; *pe; pe++)
		もし (*pe == LBRACKET) {
			/* Ignore everything between [] */
			ために (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			もし (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} 否则 もし (*pe == LBRACE)
			i++;
		否则 もし (*pe == RBRACE) {
			もし (i == 0)
				break;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	もし (i != 0 || *pe == EOS)
		戻る glob0(patbuf, pglob, limitp);

	ために (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		switch (*pm) {
		case LBRACKET:
			/* Ignore everything between [] */
			ために (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			もし (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			break;

		case LBRACE:
			i++;
			break;

		case RBRACE:
			もし (i) {
				i--;
				break;
			}
			/* FALLTHROUGH */
		case COMMA:
			もし (i && *pm == COMMA)
				break;
			否则 {
				/* Append the current string */
				ために (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				ために (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				もし (rv && rv != GLOB_NOMATCH)
					戻る rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			break;

		default:
			break;
		}
	}
	戻る 0;
}



/*
 * expand tilde from the passwd file.
 */
static const Char *
globtilde(const Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	struct passwd *pwd;
	char *h;
	const Char *p;
	Char *b, *eb;

	もし (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		戻る pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	ために (p = pattern + 1, h = (char *) patbuf;
	    h < (char *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#もし 0
	もし (h == (char *)eb)
		戻る what;
#endif

	もし (((char *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#もし 0
		もし (issetugid() != 0 || (h = getenv("HOME")) == NULL) {
#endif
		もし ((getuid() != geteuid()) || (h = getenv("HOME")) == NULL) {
			もし ((pwd = getpwuid(getuid())) == NULL)
				戻る pattern;
			否则
				h = pwd->pw_dir;
		}
	} 否则 {
		/*
		 * Expand a ~user
		 */
		もし ((pwd = getpwnam((char*) patbuf)) == NULL)
			戻る pattern;
		否则
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	ために (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	ながら (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	戻る patbuf;
}

static 整数
g_strncmp(const Char *s1, const char *s2, size_t n)
{
	整数 rv = 0;

	ながら (n--) {
		rv = *(Char *)s1 - *(const unsigned char *)s2++;
		もし (rv)
			break;
		もし (*s1++ == '\0')
			break;
	}
	戻る rv;
}

static 整数
g_charclass(const Char **patternp, Char **bufnextp)
{
	const Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	const Char *colon;
	struct cclass *cc;
	size_t len;

	もし ((colon = g_strchr(pattern, ':')) == NULL || colon[1] != ']')
		戻る 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	ために (cc = cclasses; cc->name != NULL; cc++) {
		もし (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			break;
	}
	もし (cc->name == NULL)
		戻る -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	戻る 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
static 整数
glob0(const Char *pattern, glob_t *pglob, struct glob_lim *limitp)
{
	const Char *qpatnext;
	整数 c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	ながら ((c = *qpatnext++) != EOS) {
		switch (c) {
		case LBRACKET:
			c = *qpatnext;
			もし (c == NOT)
				++qpatnext;
			もし (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == NULL) {
				*bufnext++ = LBRACKET;
				もし (c == NOT)
					--qpatnext;
				break;
			}
			*bufnext++ = M_SET;
			もし (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			do {
				もし (c == LBRACKET && *qpatnext == ':') {
					do {
						err = g_charclass(&qpatnext,
						    &bufnext);
						もし (err)
							break;
						c = *qpatnext++;
					} ながら (c == LBRACKET && *qpatnext == ':');
					もし (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						戻る GLOB_NOMATCH;
					もし (c == RBRACKET)
						break;
				}
				*bufnext++ = CHAR(c);
				もし (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} ながら ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			break;
		case QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			break;
		case STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			もし (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			break;
		default:
			*bufnext++ = CHAR(c);
			break;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	もし ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		戻る(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	もし (pglob->gl_pathc == oldpathc) {
		もし ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			戻る(globextend(pattern, pglob, limitp, NULL));
		否则
			戻る(GLOB_NOMATCH);
	}
	もし (!(pglob->gl_flags & GLOB_NOSORT)) {
		もし ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			struct glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			もし ((path_stat = calloc(n, sizeof(*path_stat))) == NULL)
				戻る GLOB_NOSPACE;
			ために (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, sizeof(*path_stat), compare_gps);
			ために (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			free(path_stat);
		} 否则 {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, sizeof(char *),
			    compare);
		}
	}
	戻る(0);
}

static 整数
compare(const void *p, const void *q)
{
	戻る(strcmp(*(char **)p, *(char **)q));
}

static 整数
compare_gps(const void *_p, const void *_q)
{
	const struct glob_path_stat *p = (const struct glob_path_stat *)_p;
	const struct glob_path_stat *q = (const struct glob_path_stat *)_q;

	戻る(strcmp(p->gps_path, q->gps_path));
}

static 整数
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, struct glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	もし (*pattern == EOS)
		戻る(0);
	戻る(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
static 整数
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, struct glob_lim *limitp)
{
	struct stat sb;
	Char *p, *q;
	整数 anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	ために (anymeta = 0;;) {
		もし (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			もし ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				戻る(GLOB_NOSPACE);
			}
			もし (g_lstat(pathbuf, &sb, pglob))
				戻る(0);

			もし (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				もし (pathend+1 > pathend_last)
					戻る (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			戻る(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		ながら (*p != EOS && *p != SEP) {
			もし (ismeta(*p))
				anymeta = 1;
			もし (q+1 > pathend_last)
				戻る (1);
			*q++ = *p++;
		}

		もし (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			ながら (*pattern == SEP) {
				もし (pathend+1 > pathend_last)
					戻る (1);
				*pathend++ = *pattern++;
			}
		} 否则
			/* Need expansion, recurse. */
			戻る(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

static 整数
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    struct glob_lim *limitp)
{
	struct dirent *dp;
	DIR *dirp;
	整数 err;
	char buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	struct dirent *(*readdirfunc)(void *);

	もし (pathend > pathend_last)
		戻る (1);
	*pathend = EOS;
	errno = 0;

	もし ((dirp = g_opendir(pathbuf, pglob)) == NULL) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		もし (pglob->gl_errfunc) {
			もし (g_Ctoc(pathbuf, buf, sizeof(buf)))
				戻る(GLOB_ABORTED);
			もし (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				戻る(GLOB_ABORTED);
		}
		戻る(0);
	}

	err = 0;

	/* Search directory for matching names. */
	もし (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	否则
		readdirfunc = (struct dirent *(*)(void *))readdir;
	ながら ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		もし ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			break;
		}

		/* Initial DOT must be matched literally. */
		もし (dp->d_name[0] == DOT && *pattern != DOT)
			continue;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		ながら (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		もし (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			break;
		}

		もし (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			continue;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		もし (err)
			break;
	}

	もし (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	否则
		closedir(dirp);
	戻る(err);
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
static 整数
globextend(const Char *path, glob_t *pglob, struct glob_lim *limitp,
    struct stat *sb)
{
	char **pathv;
	size_t i, newn, len;
	char *copy = NULL;
	const Char *p;
	struct stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	もし (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / sizeof(*pathv) <= newn ||
	    SIZE_MAX / sizeof(*statv) <= newn) {
 nospace:
		ために (i = pglob->gl_offs; i < newn - 2; i++) {
			もし (pglob->gl_pathv && pglob->gl_pathv[i])
				free(pglob->gl_pathv[i]);
			もし ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				free(pglob->gl_statv[i]);
		}
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
		free(pglob->gl_statv);
		pglob->gl_statv = NULL;
		戻る(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, sizeof(*pathv));
	もし (pathv == NULL)
		goto nospace;
	もし (pglob->gl_pathv == NULL && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		ために (i = pglob->gl_offs; i > 0; i--)
			*--pathv = NULL;
	}
	pglob->gl_pathv = pathv;

	もし ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, sizeof(*statv));
		もし (statv == NULL)
			goto nospace;
		もし (pglob->gl_statv == NULL && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			ために (i = pglob->gl_offs; i > 0; i--)
				*--statv = NULL;
		}
		pglob->gl_statv = statv;
		もし (sb == NULL)
			statv[pglob->gl_offs + pglob->gl_pathc] = NULL;
		否则 {
			limitp->glim_malloc += sizeof(**statv);
			もし ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				戻る(GLOB_NOSPACE);
			}
			もし ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(sizeof(**statv))) == NULL)
				goto copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    sizeof(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = NULL;
	}

	ために (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	もし ((copy = malloc(len)) != NULL) {
		もし (g_Ctoc(path, copy, len)) {
			free(copy);
			戻る(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;

	もし ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * sizeof(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		戻る(GLOB_NOSPACE);
	}
 copy_error:
	戻る(copy == NULL ? GLOB_NOSPACE : 0);
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
static 整数
match(Char *name, Char *pat, Char *patend)
{
	整数 ok, negate_range;
	Char c, k;
	Char *nextp = NULL;
	Char *nextn = NULL;

loop:
	ながら (pat < patend) {
		c = *pat++;
		switch (c & M_MASK) {
		case M_ALL:
			ながら (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			もし (pat == patend)
				戻る(1);
			もし (*name == EOS)
				戻る(0);
			nextn = name + 1;
			nextp = pat - 1;
			break;
		case M_ONE:
			もし (*name++ == EOS)
				goto fail;
			break;
		case M_SET:
			ok = 0;
			もし ((k = *name++) == EOS)
				goto fail;
			もし ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			ながら (((c = *pat++) & M_MASK) != M_END) {
				もし ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					もし (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				もし ((*pat & M_MASK) == M_RNG) {
					もし (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} 否则 もし (c == k)
					ok = 1;
			}
			もし (ok == negate_range)
				goto fail;
			break;
		default:
			もし (*name++ != c)
				goto fail;
			break;
		}
	}
	もし (*name == EOS)
		戻る(1);

fail:
	もし (nextn) {
		pat = nextp;
		name = nextn;
		goto loop;
	}
	戻る(0);
}

/* Free allocated data belonging to a glob_t structure. */
void
globfree(glob_t *pglob)
{
	size_t i;
	char **pp;

	もし (pglob->gl_pathv != NULL) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		ために (i = pglob->gl_pathc; i--; ++pp)
			free(*pp);
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
	}
	もし (pglob->gl_statv != NULL) {
		ために (i = 0; i < pglob->gl_pathc; i++) {
			free(pglob->gl_statv[i]);
		}
		free(pglob->gl_statv);
		pglob->gl_statv = NULL;
	}
}

static DIR *
g_opendir(Char *str, glob_t *pglob)
{
	char buf[PATH_MAX];

	もし (!*str)
		strlcpy(buf, ".", sizeof buf);
	否则 {
		もし (g_Ctoc(str, buf, sizeof(buf)))
			戻る(NULL);
	}

	もし (pglob->gl_flags & GLOB_ALTDIRFUNC)
		戻る((*pglob->gl_opendir)(buf));

	戻る(opendir(buf));
}

static 整数
g_lstat(Char *fn, struct stat *sb, glob_t *pglob)
{
	char buf[PATH_MAX];

	もし (g_Ctoc(fn, buf, sizeof(buf)))
		戻る(-1);
	もし (pglob->gl_flags & GLOB_ALTDIRFUNC)
		戻る((*pglob->gl_lstat)(buf, sb));
	戻る(lstat(buf, sb));
}

static 整数
g_stat(Char *fn, struct stat *sb, glob_t *pglob)
{
	char buf[PATH_MAX];

	もし (g_Ctoc(fn, buf, sizeof(buf)))
		戻る(-1);
	もし (pglob->gl_flags & GLOB_ALTDIRFUNC)
		戻る((*pglob->gl_stat)(buf, sb));
	戻る(stat(buf, sb));
}

static Char *
g_strchr(const Char *str, 整数 ch)
{
	do {
		もし (*str == ch)
			戻る ((Char *)str);
	} ながら (*str++);
	戻る (NULL);
}

static 整数
g_Ctoc(const Char *str, char *buf, size_t len)
{

	ながら (len--) {
		もし ((*buf++ = *str++) == EOS)
			戻る (0);
	}
	戻る (1);
}

#ifdef DEBUG
static void
qprintf(const char *str, Char *s)
{
	Char *p;

	(void)printf("%s:\n", str);
	ために (p = s; *p; p++)
		(void)printf("%c", CHAR(*p));
	(void)printf("\n");
	ために (p = s; *p; p++)
		(void)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(void)printf("\n");
	ために (p = s; *p; p++)
		(void)printf("%c", ismeta(*p) ? '_' : ' ');
	(void)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
