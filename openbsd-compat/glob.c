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

#если !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
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

#иначе

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

static целое	 compare(const void *, const void *);
static целое	 compare_gps(const void *, const void *);
static целое	 g_Ctoc(const Char *, char *, size_t);
static целое	 g_lstat(Char *, struct stat *, glob_t *);
static DIR	*g_opendir(Char *, glob_t *);
static Char	*g_strchr(const Char *, целое);
static целое	 g_strncmp(const Char *, const char *, size_t);
static целое	 g_stat(Char *, struct stat *, glob_t *);
static целое	 glob0(const Char *, glob_t *, struct glob_lim *);
static целое	 glob1(Char *, Char *, glob_t *, struct glob_lim *);
static целое	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, struct glob_lim *);
static целое	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, struct glob_lim *);
static целое	 globextend(const Char *, glob_t *, struct glob_lim *,
		    struct stat *);
static const Char *
		 globtilde(const Char *, Char *, size_t, glob_t *);
static целое	 globexp1(const Char *, glob_t *, struct glob_lim *);
static целое	 globexp2(const Char *, const Char *, glob_t *,
		    struct glob_lim *);
static целое	 match(Char *, Char *, Char *);
#ifdef DEBUG
static void	 qprintf(const char *, Char *);
#endif

целое
glob(const char *pattern, целое flags, целое (*errfunc)(const char *, целое),
    glob_t *pglob)
{
	const u_char *patnext;
	целое c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	struct glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	если (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = NULL;
		pglob->gl_statv = NULL;
		если (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	если (strnlen(pattern, PATH_MAX) == PATH_MAX)
		вернуть(GLOB_NOMATCH);

	если (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		вернуть GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	если (flags & GLOB_NOESCAPE)
		пока (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	иначе {
		/* Protect the quoted characters. */
		пока (bufnext < bufend && (c = *patnext++) != EOS)
			если (c == QUOTE) {
				если ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} иначе
				*bufnext++ = c;
	}
	*bufnext = EOS;

	если (flags & GLOB_BRACE)
		вернуть globexp1(patbuf, pglob, &limit);
	иначе
		вернуть glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
static целое
globexp1(const Char *pattern, glob_t *pglob, struct glob_lim *limitp)
{
	const Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	если (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		вернуть glob0(pattern, pglob, limitp);

	если ((ptr = (const Char *) g_strchr(ptr, LBRACE)) != NULL)
		вернуть globexp2(ptr, pattern, pglob, limitp);

	вернуть glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
static целое
globexp2(const Char *ptr, const Char *pattern, glob_t *pglob,
    struct glob_lim *limitp)
{
	целое     i, rv;
	Char   *lm, *ls;
	const Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	для (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	для (i = 0, pe = ++ptr; *pe; pe++)
		если (*pe == LBRACKET) {
			/* Ignore everything between [] */
			для (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			если (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} иначе если (*pe == LBRACE)
			i++;
		иначе если (*pe == RBRACE) {
			если (i == 0)
				break;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	если (i != 0 || *pe == EOS)
		вернуть glob0(patbuf, pglob, limitp);

	для (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		switch (*pm) {
		case LBRACKET:
			/* Ignore everything between [] */
			для (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			если (*pm == EOS) {
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
			если (i) {
				i--;
				break;
			}
			/* FALLTHROUGH */
		case COMMA:
			если (i && *pm == COMMA)
				break;
			иначе {
				/* Append the current string */
				для (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				для (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				если (rv && rv != GLOB_NOMATCH)
					вернуть rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			break;

		default:
			break;
		}
	}
	вернуть 0;
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

	если (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		вернуть pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	для (p = pattern + 1, h = (char *) patbuf;
	    h < (char *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#если 0
	если (h == (char *)eb)
		вернуть what;
#endif

	если (((char *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#если 0
		если (issetugid() != 0 || (h = getenv("HOME")) == NULL) {
#endif
		если ((getuid() != geteuid()) || (h = getenv("HOME")) == NULL) {
			если ((pwd = getpwuid(getuid())) == NULL)
				вернуть pattern;
			иначе
				h = pwd->pw_dir;
		}
	} иначе {
		/*
		 * Expand a ~user
		 */
		если ((pwd = getpwnam((char*) patbuf)) == NULL)
			вернуть pattern;
		иначе
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	для (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	пока (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	вернуть patbuf;
}

static целое
g_strncmp(const Char *s1, const char *s2, size_t n)
{
	целое rv = 0;

	пока (n--) {
		rv = *(Char *)s1 - *(const unsigned char *)s2++;
		если (rv)
			break;
		если (*s1++ == '\0')
			break;
	}
	вернуть rv;
}

static целое
g_charclass(const Char **patternp, Char **bufnextp)
{
	const Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	const Char *colon;
	struct cclass *cc;
	size_t len;

	если ((colon = g_strchr(pattern, ':')) == NULL || colon[1] != ']')
		вернуть 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	для (cc = cclasses; cc->name != NULL; cc++) {
		если (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			break;
	}
	если (cc->name == NULL)
		вернуть -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	вернуть 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
static целое
glob0(const Char *pattern, glob_t *pglob, struct glob_lim *limitp)
{
	const Char *qpatnext;
	целое c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	пока ((c = *qpatnext++) != EOS) {
		switch (c) {
		case LBRACKET:
			c = *qpatnext;
			если (c == NOT)
				++qpatnext;
			если (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == NULL) {
				*bufnext++ = LBRACKET;
				если (c == NOT)
					--qpatnext;
				break;
			}
			*bufnext++ = M_SET;
			если (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			do {
				если (c == LBRACKET && *qpatnext == ':') {
					do {
						err = g_charclass(&qpatnext,
						    &bufnext);
						если (err)
							break;
						c = *qpatnext++;
					} пока (c == LBRACKET && *qpatnext == ':');
					если (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						вернуть GLOB_NOMATCH;
					если (c == RBRACKET)
						break;
				}
				*bufnext++ = CHAR(c);
				если (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} пока ((c = *qpatnext++) != RBRACKET);
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
			если (bufnext == patbuf || bufnext[-1] != M_ALL)
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

	если ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		вернуть(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	если (pglob->gl_pathc == oldpathc) {
		если ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			вернуть(globextend(pattern, pglob, limitp, NULL));
		иначе
			вернуть(GLOB_NOMATCH);
	}
	если (!(pglob->gl_flags & GLOB_NOSORT)) {
		если ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			struct glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			если ((path_stat = calloc(n, sizeof(*path_stat))) == NULL)
				вернуть GLOB_NOSPACE;
			для (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, sizeof(*path_stat), compare_gps);
			для (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			free(path_stat);
		} иначе {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, sizeof(char *),
			    compare);
		}
	}
	вернуть(0);
}

static целое
compare(const void *p, const void *q)
{
	вернуть(strcmp(*(char **)p, *(char **)q));
}

static целое
compare_gps(const void *_p, const void *_q)
{
	const struct glob_path_stat *p = (const struct glob_path_stat *)_p;
	const struct glob_path_stat *q = (const struct glob_path_stat *)_q;

	вернуть(strcmp(p->gps_path, q->gps_path));
}

static целое
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, struct glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	если (*pattern == EOS)
		вернуть(0);
	вернуть(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
static целое
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, struct glob_lim *limitp)
{
	struct stat sb;
	Char *p, *q;
	целое anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	для (anymeta = 0;;) {
		если (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			если ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				вернуть(GLOB_NOSPACE);
			}
			если (g_lstat(pathbuf, &sb, pglob))
				вернуть(0);

			если (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				если (pathend+1 > pathend_last)
					вернуть (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			вернуть(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		пока (*p != EOS && *p != SEP) {
			если (ismeta(*p))
				anymeta = 1;
			если (q+1 > pathend_last)
				вернуть (1);
			*q++ = *p++;
		}

		если (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			пока (*pattern == SEP) {
				если (pathend+1 > pathend_last)
					вернуть (1);
				*pathend++ = *pattern++;
			}
		} иначе
			/* Need expansion, recurse. */
			вернуть(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

static целое
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    struct glob_lim *limitp)
{
	struct dirent *dp;
	DIR *dirp;
	целое err;
	char buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	struct dirent *(*readdirfunc)(void *);

	если (pathend > pathend_last)
		вернуть (1);
	*pathend = EOS;
	errno = 0;

	если ((dirp = g_opendir(pathbuf, pglob)) == NULL) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		если (pglob->gl_errfunc) {
			если (g_Ctoc(pathbuf, buf, sizeof(buf)))
				вернуть(GLOB_ABORTED);
			если (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				вернуть(GLOB_ABORTED);
		}
		вернуть(0);
	}

	err = 0;

	/* Search directory for matching names. */
	если (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	иначе
		readdirfunc = (struct dirent *(*)(void *))readdir;
	пока ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		если ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			break;
		}

		/* Initial DOT must be matched literally. */
		если (dp->d_name[0] == DOT && *pattern != DOT)
			continue;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		пока (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		если (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			break;
		}

		если (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			continue;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		если (err)
			break;
	}

	если (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	иначе
		closedir(dirp);
	вернуть(err);
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
static целое
globextend(const Char *path, glob_t *pglob, struct glob_lim *limitp,
    struct stat *sb)
{
	char **pathv;
	size_t i, newn, len;
	char *copy = NULL;
	const Char *p;
	struct stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	если (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / sizeof(*pathv) <= newn ||
	    SIZE_MAX / sizeof(*statv) <= newn) {
 nospace:
		для (i = pglob->gl_offs; i < newn - 2; i++) {
			если (pglob->gl_pathv && pglob->gl_pathv[i])
				free(pglob->gl_pathv[i]);
			если ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				free(pglob->gl_statv[i]);
		}
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
		free(pglob->gl_statv);
		pglob->gl_statv = NULL;
		вернуть(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, sizeof(*pathv));
	если (pathv == NULL)
		goto nospace;
	если (pglob->gl_pathv == NULL && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		для (i = pglob->gl_offs; i > 0; i--)
			*--pathv = NULL;
	}
	pglob->gl_pathv = pathv;

	если ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, sizeof(*statv));
		если (statv == NULL)
			goto nospace;
		если (pglob->gl_statv == NULL && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			для (i = pglob->gl_offs; i > 0; i--)
				*--statv = NULL;
		}
		pglob->gl_statv = statv;
		если (sb == NULL)
			statv[pglob->gl_offs + pglob->gl_pathc] = NULL;
		иначе {
			limitp->glim_malloc += sizeof(**statv);
			если ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				вернуть(GLOB_NOSPACE);
			}
			если ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(sizeof(**statv))) == NULL)
				goto copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    sizeof(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = NULL;
	}

	для (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	если ((copy = malloc(len)) != NULL) {
		если (g_Ctoc(path, copy, len)) {
			free(copy);
			вернуть(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;

	если ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * sizeof(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		вернуть(GLOB_NOSPACE);
	}
 copy_error:
	вернуть(copy == NULL ? GLOB_NOSPACE : 0);
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
static целое
match(Char *name, Char *pat, Char *patend)
{
	целое ok, negate_range;
	Char c, k;
	Char *nextp = NULL;
	Char *nextn = NULL;

loop:
	пока (pat < patend) {
		c = *pat++;
		switch (c & M_MASK) {
		case M_ALL:
			пока (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			если (pat == patend)
				вернуть(1);
			если (*name == EOS)
				вернуть(0);
			nextn = name + 1;
			nextp = pat - 1;
			break;
		case M_ONE:
			если (*name++ == EOS)
				goto fail;
			break;
		case M_SET:
			ok = 0;
			если ((k = *name++) == EOS)
				goto fail;
			если ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			пока (((c = *pat++) & M_MASK) != M_END) {
				если ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					если (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				если ((*pat & M_MASK) == M_RNG) {
					если (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} иначе если (c == k)
					ok = 1;
			}
			если (ok == negate_range)
				goto fail;
			break;
		default:
			если (*name++ != c)
				goto fail;
			break;
		}
	}
	если (*name == EOS)
		вернуть(1);

fail:
	если (nextn) {
		pat = nextp;
		name = nextn;
		goto loop;
	}
	вернуть(0);
}

/* Free allocated data belonging to a glob_t structure. */
void
globfree(glob_t *pglob)
{
	size_t i;
	char **pp;

	если (pglob->gl_pathv != NULL) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		для (i = pglob->gl_pathc; i--; ++pp)
			free(*pp);
		free(pglob->gl_pathv);
		pglob->gl_pathv = NULL;
	}
	если (pglob->gl_statv != NULL) {
		для (i = 0; i < pglob->gl_pathc; i++) {
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

	если (!*str)
		strlcpy(buf, ".", sizeof buf);
	иначе {
		если (g_Ctoc(str, buf, sizeof(buf)))
			вернуть(NULL);
	}

	если (pglob->gl_flags & GLOB_ALTDIRFUNC)
		вернуть((*pglob->gl_opendir)(buf));

	вернуть(opendir(buf));
}

static целое
g_lstat(Char *fn, struct stat *sb, glob_t *pglob)
{
	char buf[PATH_MAX];

	если (g_Ctoc(fn, buf, sizeof(buf)))
		вернуть(-1);
	если (pglob->gl_flags & GLOB_ALTDIRFUNC)
		вернуть((*pglob->gl_lstat)(buf, sb));
	вернуть(lstat(buf, sb));
}

static целое
g_stat(Char *fn, struct stat *sb, glob_t *pglob)
{
	char buf[PATH_MAX];

	если (g_Ctoc(fn, buf, sizeof(buf)))
		вернуть(-1);
	если (pglob->gl_flags & GLOB_ALTDIRFUNC)
		вернуть((*pglob->gl_stat)(buf, sb));
	вернуть(stat(buf, sb));
}

static Char *
g_strchr(const Char *str, целое ch)
{
	do {
		если (*str == ch)
			вернуть ((Char *)str);
	} пока (*str++);
	вернуть (NULL);
}

static целое
g_Ctoc(const Char *str, char *buf, size_t len)
{

	пока (len--) {
		если ((*buf++ = *str++) == EOS)
			вернуть (0);
	}
	вернуть (1);
}

#ifdef DEBUG
static void
qprintf(const char *str, Char *s)
{
	Char *p;

	(void)printf("%s:\n", str);
	для (p = s; *p; p++)
		(void)printf("%c", CHAR(*p));
	(void)printf("\n");
	для (p = s; *p; p++)
		(void)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(void)printf("\n");
	для (p = s; *p; p++)
		(void)printf("%c", ismeta(*p) ? '_' : ' ');
	(void)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
