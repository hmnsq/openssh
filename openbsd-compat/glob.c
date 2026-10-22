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

#شامل "includes.h"
#شامل "glob.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <dirent.h>
#شامل <ctype.h>
#شامل <errno.h>
#شامل <limits.h>
#شامل <pwd.h>
#شامل <stdlib.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <unistd.h>

#اگر !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#شامل "charclass.h"

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

تعریفنوع u_short Char;

#وگرنه

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

تعریفنوع نویسه Char;

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

ساختار glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

ساختار glob_path_stat {
	نویسه		*gps_path;
	ساختار stat	*gps_stat;
};

ایستا صحیح	 compare(ثابت تهی *, ثابت تهی *);
ایستا صحیح	 compare_gps(ثابت تهی *, ثابت تهی *);
ایستا صحیح	 g_Ctoc(ثابت Char *, نویسه *, size_t);
ایستا صحیح	 g_lstat(Char *, ساختار stat *, glob_t *);
ایستا DIR	*g_opendir(Char *, glob_t *);
ایستا Char	*g_strchr(ثابت Char *, صحیح);
ایستا صحیح	 g_strncmp(ثابت Char *, ثابت نویسه *, size_t);
ایستا صحیح	 g_stat(Char *, ساختار stat *, glob_t *);
ایستا صحیح	 glob0(ثابت Char *, glob_t *, ساختار glob_lim *);
ایستا صحیح	 glob1(Char *, Char *, glob_t *, ساختار glob_lim *);
ایستا صحیح	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, ساختار glob_lim *);
ایستا صحیح	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, ساختار glob_lim *);
ایستا صحیح	 globextend(ثابت Char *, glob_t *, ساختار glob_lim *,
		    ساختار stat *);
ایستا ثابت Char *
		 globtilde(ثابت Char *, Char *, size_t, glob_t *);
ایستا صحیح	 globexp1(ثابت Char *, glob_t *, ساختار glob_lim *);
ایستا صحیح	 globexp2(ثابت Char *, ثابت Char *, glob_t *,
		    ساختار glob_lim *);
ایستا صحیح	 match(Char *, Char *, Char *);
#ifdef DEBUG
ایستا تهی	 qprintf(ثابت نویسه *, Char *);
#endif

صحیح
glob(ثابت نویسه *pattern, صحیح flags, صحیح (*errfunc)(ثابت نویسه *, صحیح),
    glob_t *pglob)
{
	ثابت u_char *patnext;
	صحیح c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	ساختار glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	اگر (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = پوچ;
		pglob->gl_statv = پوچ;
		اگر (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	اگر (strnlen(pattern, PATH_MAX) == PATH_MAX)
		بازگشت(GLOB_NOMATCH);

	اگر (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		بازگشت GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	اگر (flags & GLOB_NOESCAPE)
		وقتی (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	وگرنه {
		/* Protect the quoted characters. */
		وقتی (bufnext < bufend && (c = *patnext++) != EOS)
			اگر (c == QUOTE) {
				اگر ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} وگرنه
				*bufnext++ = c;
	}
	*bufnext = EOS;

	اگر (flags & GLOB_BRACE)
		بازگشت globexp1(patbuf, pglob, &limit);
	وگرنه
		بازگشت glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
ایستا صحیح
globexp1(ثابت Char *pattern, glob_t *pglob, ساختار glob_lim *limitp)
{
	ثابت Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	اگر (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		بازگشت glob0(pattern, pglob, limitp);

	اگر ((ptr = (ثابت Char *) g_strchr(ptr, LBRACE)) != پوچ)
		بازگشت globexp2(ptr, pattern, pglob, limitp);

	بازگشت glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
ایستا صحیح
globexp2(ثابت Char *ptr, ثابت Char *pattern, glob_t *pglob,
    ساختار glob_lim *limitp)
{
	صحیح     i, rv;
	Char   *lm, *ls;
	ثابت Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	برای (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	برای (i = 0, pe = ++ptr; *pe; pe++)
		اگر (*pe == LBRACKET) {
			/* Ignore everything between [] */
			برای (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			اگر (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} وگرنه اگر (*pe == LBRACE)
			i++;
		وگرنه اگر (*pe == RBRACE) {
			اگر (i == 0)
				بشکن;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	اگر (i != 0 || *pe == EOS)
		بازگشت glob0(patbuf, pglob, limitp);

	برای (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		انتخاب (*pm) {
		حالت LBRACKET:
			/* Ignore everything between [] */
			برای (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			اگر (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			بشکن;

		حالت LBRACE:
			i++;
			بشکن;

		حالت RBRACE:
			اگر (i) {
				i--;
				بشکن;
			}
			/* FALLTHROUGH */
		حالت COMMA:
			اگر (i && *pm == COMMA)
				بشکن;
			وگرنه {
				/* Append the current string */
				برای (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				برای (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				اگر (rv && rv != GLOB_NOMATCH)
					بازگشت rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			بشکن;

		پیشفرض:
			بشکن;
		}
	}
	بازگشت 0;
}



/*
 * expand tilde from the passwd file.
 */
ایستا ثابت Char *
globtilde(ثابت Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	ساختار passwd *pwd;
	نویسه *h;
	ثابت Char *p;
	Char *b, *eb;

	اگر (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		بازگشت pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	برای (p = pattern + 1, h = (نویسه *) patbuf;
	    h < (نویسه *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#اگر 0
	اگر (h == (نویسه *)eb)
		بازگشت what;
#endif

	اگر (((نویسه *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#اگر 0
		اگر (issetugid() != 0 || (h = getenv("HOME")) == پوچ) {
#endif
		اگر ((getuid() != geteuid()) || (h = getenv("HOME")) == پوچ) {
			اگر ((pwd = getpwuid(getuid())) == پوچ)
				بازگشت pattern;
			وگرنه
				h = pwd->pw_dir;
		}
	} وگرنه {
		/*
		 * Expand a ~user
		 */
		اگر ((pwd = getpwnam((نویسه*) patbuf)) == پوچ)
			بازگشت pattern;
		وگرنه
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	برای (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	وقتی (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	بازگشت patbuf;
}

ایستا صحیح
g_strncmp(ثابت Char *s1, ثابت نویسه *s2, size_t n)
{
	صحیح rv = 0;

	وقتی (n--) {
		rv = *(Char *)s1 - *(ثابت unsigned نویسه *)s2++;
		اگر (rv)
			بشکن;
		اگر (*s1++ == '\0')
			بشکن;
	}
	بازگشت rv;
}

ایستا صحیح
g_charclass(ثابت Char **patternp, Char **bufnextp)
{
	ثابت Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	ثابت Char *colon;
	ساختار cclass *cc;
	size_t len;

	اگر ((colon = g_strchr(pattern, ':')) == پوچ || colon[1] != ']')
		بازگشت 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	برای (cc = cclasses; cc->name != پوچ; cc++) {
		اگر (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			بشکن;
	}
	اگر (cc->name == پوچ)
		بازگشت -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	بازگشت 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
ایستا صحیح
glob0(ثابت Char *pattern, glob_t *pglob, ساختار glob_lim *limitp)
{
	ثابت Char *qpatnext;
	صحیح c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	وقتی ((c = *qpatnext++) != EOS) {
		انتخاب (c) {
		حالت LBRACKET:
			c = *qpatnext;
			اگر (c == NOT)
				++qpatnext;
			اگر (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == پوچ) {
				*bufnext++ = LBRACKET;
				اگر (c == NOT)
					--qpatnext;
				بشکن;
			}
			*bufnext++ = M_SET;
			اگر (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			انجامبده {
				اگر (c == LBRACKET && *qpatnext == ':') {
					انجامبده {
						err = g_charclass(&qpatnext,
						    &bufnext);
						اگر (err)
							بشکن;
						c = *qpatnext++;
					} وقتی (c == LBRACKET && *qpatnext == ':');
					اگر (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						بازگشت GLOB_NOMATCH;
					اگر (c == RBRACKET)
						بشکن;
				}
				*bufnext++ = CHAR(c);
				اگر (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} وقتی ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			بشکن;
		حالت QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			بشکن;
		حالت STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			اگر (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			بشکن;
		پیشفرض:
			*bufnext++ = CHAR(c);
			بشکن;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	اگر ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		بازگشت(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	اگر (pglob->gl_pathc == oldpathc) {
		اگر ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			بازگشت(globextend(pattern, pglob, limitp, پوچ));
		وگرنه
			بازگشت(GLOB_NOMATCH);
	}
	اگر (!(pglob->gl_flags & GLOB_NOSORT)) {
		اگر ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			ساختار glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			اگر ((path_stat = calloc(n, اندازه(*path_stat))) == پوچ)
				بازگشت GLOB_NOSPACE;
			برای (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, اندازه(*path_stat), compare_gps);
			برای (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			آزاد(path_stat);
		} وگرنه {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, اندازه(نویسه *),
			    compare);
		}
	}
	بازگشت(0);
}

ایستا صحیح
compare(ثابت تهی *p, ثابت تهی *q)
{
	بازگشت(strcmp(*(نویسه **)p, *(نویسه **)q));
}

ایستا صحیح
compare_gps(ثابت تهی *_p, ثابت تهی *_q)
{
	ثابت ساختار glob_path_stat *p = (ثابت ساختار glob_path_stat *)_p;
	ثابت ساختار glob_path_stat *q = (ثابت ساختار glob_path_stat *)_q;

	بازگشت(strcmp(p->gps_path, q->gps_path));
}

ایستا صحیح
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, ساختار glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	اگر (*pattern == EOS)
		بازگشت(0);
	بازگشت(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
ایستا صحیح
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, ساختار glob_lim *limitp)
{
	ساختار stat sb;
	Char *p, *q;
	صحیح anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	برای (anymeta = 0;;) {
		اگر (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			اگر ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				بازگشت(GLOB_NOSPACE);
			}
			اگر (g_lstat(pathbuf, &sb, pglob))
				بازگشت(0);

			اگر (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				اگر (pathend+1 > pathend_last)
					بازگشت (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			بازگشت(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		وقتی (*p != EOS && *p != SEP) {
			اگر (ismeta(*p))
				anymeta = 1;
			اگر (q+1 > pathend_last)
				بازگشت (1);
			*q++ = *p++;
		}

		اگر (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			وقتی (*pattern == SEP) {
				اگر (pathend+1 > pathend_last)
					بازگشت (1);
				*pathend++ = *pattern++;
			}
		} وگرنه
			/* Need expansion, recurse. */
			بازگشت(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

ایستا صحیح
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    ساختار glob_lim *limitp)
{
	ساختار dirent *dp;
	DIR *dirp;
	صحیح err;
	نویسه buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	ساختار dirent *(*readdirfunc)(تهی *);

	اگر (pathend > pathend_last)
		بازگشت (1);
	*pathend = EOS;
	errno = 0;

	اگر ((dirp = g_opendir(pathbuf, pglob)) == پوچ) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		اگر (pglob->gl_errfunc) {
			اگر (g_Ctoc(pathbuf, buf, اندازه(buf)))
				بازگشت(GLOB_ABORTED);
			اگر (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				بازگشت(GLOB_ABORTED);
		}
		بازگشت(0);
	}

	err = 0;

	/* Search directory for matching names. */
	اگر (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	وگرنه
		readdirfunc = (ساختار dirent *(*)(تهی *))readdir;
	وقتی ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		اگر ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			بشکن;
		}

		/* Initial DOT must be matched literally. */
		اگر (dp->d_name[0] == DOT && *pattern != DOT)
			ادامه;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		وقتی (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		اگر (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			بشکن;
		}

		اگر (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			ادامه;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		اگر (err)
			بشکن;
	}

	اگر (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	وگرنه
		closedir(dirp);
	بازگشت(err);
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
ایستا صحیح
globextend(ثابت Char *path, glob_t *pglob, ساختار glob_lim *limitp,
    ساختار stat *sb)
{
	نویسه **pathv;
	size_t i, newn, len;
	نویسه *copy = پوچ;
	ثابت Char *p;
	ساختار stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	اگر (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / اندازه(*pathv) <= newn ||
	    SIZE_MAX / اندازه(*statv) <= newn) {
 nospace:
		برای (i = pglob->gl_offs; i < newn - 2; i++) {
			اگر (pglob->gl_pathv && pglob->gl_pathv[i])
				آزاد(pglob->gl_pathv[i]);
			اگر ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				آزاد(pglob->gl_statv[i]);
		}
		آزاد(pglob->gl_pathv);
		pglob->gl_pathv = پوچ;
		آزاد(pglob->gl_statv);
		pglob->gl_statv = پوچ;
		بازگشت(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, اندازه(*pathv));
	اگر (pathv == پوچ)
		برو nospace;
	اگر (pglob->gl_pathv == پوچ && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		برای (i = pglob->gl_offs; i > 0; i--)
			*--pathv = پوچ;
	}
	pglob->gl_pathv = pathv;

	اگر ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, اندازه(*statv));
		اگر (statv == پوچ)
			برو nospace;
		اگر (pglob->gl_statv == پوچ && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			برای (i = pglob->gl_offs; i > 0; i--)
				*--statv = پوچ;
		}
		pglob->gl_statv = statv;
		اگر (sb == پوچ)
			statv[pglob->gl_offs + pglob->gl_pathc] = پوچ;
		وگرنه {
			limitp->glim_malloc += اندازه(**statv);
			اگر ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				بازگشت(GLOB_NOSPACE);
			}
			اگر ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(اندازه(**statv))) == پوچ)
				برو copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    اندازه(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = پوچ;
	}

	برای (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	اگر ((copy = malloc(len)) != پوچ) {
		اگر (g_Ctoc(path, copy, len)) {
			آزاد(copy);
			بازگشت(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = پوچ;

	اگر ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * اندازه(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		بازگشت(GLOB_NOSPACE);
	}
 copy_error:
	بازگشت(copy == پوچ ? GLOB_NOSPACE : 0);
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
ایستا صحیح
match(Char *name, Char *pat, Char *patend)
{
	صحیح ok, negate_range;
	Char c, k;
	Char *nextp = پوچ;
	Char *nextn = پوچ;

loop:
	وقتی (pat < patend) {
		c = *pat++;
		انتخاب (c & M_MASK) {
		حالت M_ALL:
			وقتی (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			اگر (pat == patend)
				بازگشت(1);
			اگر (*name == EOS)
				بازگشت(0);
			nextn = name + 1;
			nextp = pat - 1;
			بشکن;
		حالت M_ONE:
			اگر (*name++ == EOS)
				برو fail;
			بشکن;
		حالت M_SET:
			ok = 0;
			اگر ((k = *name++) == EOS)
				برو fail;
			اگر ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			وقتی (((c = *pat++) & M_MASK) != M_END) {
				اگر ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					اگر (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				اگر ((*pat & M_MASK) == M_RNG) {
					اگر (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} وگرنه اگر (c == k)
					ok = 1;
			}
			اگر (ok == negate_range)
				برو fail;
			بشکن;
		پیشفرض:
			اگر (*name++ != c)
				برو fail;
			بشکن;
		}
	}
	اگر (*name == EOS)
		بازگشت(1);

fail:
	اگر (nextn) {
		pat = nextp;
		name = nextn;
		برو loop;
	}
	بازگشت(0);
}

/* Free allocated data belonging to a glob_t structure. */
تهی
globfree(glob_t *pglob)
{
	size_t i;
	نویسه **pp;

	اگر (pglob->gl_pathv != پوچ) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		برای (i = pglob->gl_pathc; i--; ++pp)
			آزاد(*pp);
		آزاد(pglob->gl_pathv);
		pglob->gl_pathv = پوچ;
	}
	اگر (pglob->gl_statv != پوچ) {
		برای (i = 0; i < pglob->gl_pathc; i++) {
			آزاد(pglob->gl_statv[i]);
		}
		آزاد(pglob->gl_statv);
		pglob->gl_statv = پوچ;
	}
}

ایستا DIR *
g_opendir(Char *str, glob_t *pglob)
{
	نویسه buf[PATH_MAX];

	اگر (!*str)
		strlcpy(buf, ".", اندازه buf);
	وگرنه {
		اگر (g_Ctoc(str, buf, اندازه(buf)))
			بازگشت(پوچ);
	}

	اگر (pglob->gl_flags & GLOB_ALTDIRFUNC)
		بازگشت((*pglob->gl_opendir)(buf));

	بازگشت(opendir(buf));
}

ایستا صحیح
g_lstat(Char *fn, ساختار stat *sb, glob_t *pglob)
{
	نویسه buf[PATH_MAX];

	اگر (g_Ctoc(fn, buf, اندازه(buf)))
		بازگشت(-1);
	اگر (pglob->gl_flags & GLOB_ALTDIRFUNC)
		بازگشت((*pglob->gl_lstat)(buf, sb));
	بازگشت(lstat(buf, sb));
}

ایستا صحیح
g_stat(Char *fn, ساختار stat *sb, glob_t *pglob)
{
	نویسه buf[PATH_MAX];

	اگر (g_Ctoc(fn, buf, اندازه(buf)))
		بازگشت(-1);
	اگر (pglob->gl_flags & GLOB_ALTDIRFUNC)
		بازگشت((*pglob->gl_stat)(buf, sb));
	بازگشت(stat(buf, sb));
}

ایستا Char *
g_strchr(ثابت Char *str, صحیح ch)
{
	انجامبده {
		اگر (*str == ch)
			بازگشت ((Char *)str);
	} وقتی (*str++);
	بازگشت (پوچ);
}

ایستا صحیح
g_Ctoc(ثابت Char *str, نویسه *buf, size_t len)
{

	وقتی (len--) {
		اگر ((*buf++ = *str++) == EOS)
			بازگشت (0);
	}
	بازگشت (1);
}

#ifdef DEBUG
ایستا تهی
qprintf(ثابت نویسه *str, Char *s)
{
	Char *p;

	(تهی)printf("%s:\n", str);
	برای (p = s; *p; p++)
		(تهی)printf("%c", CHAR(*p));
	(تهی)printf("\n");
	برای (p = s; *p; p++)
		(تهی)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(تهی)printf("\n");
	برای (p = s; *p; p++)
		(تهی)printf("%c", ismeta(*p) ? '_' : ' ');
	(تهی)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
