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

#ضمن "includes.h"
#ضمن "glob.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>

#ضمن <dirent.h>
#ضمن <ctype.h>
#ضمن <errno.h>
#ضمن <limits.h>
#ضمن <pwd.h>
#ضمن <stdlib.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <unistd.h>

#إذا !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#ضمن "charclass.h"

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

تعريفنوع u_short Char;

#وإلا

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

تعريفنوع حرف Char;

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

بنية glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

بنية glob_path_stat {
	حرف		*gps_path;
	بنية stat	*gps_stat;
};

ساكن صحيح	 compare(ثابت فراغ *, ثابت فراغ *);
ساكن صحيح	 compare_gps(ثابت فراغ *, ثابت فراغ *);
ساكن صحيح	 g_Ctoc(ثابت Char *, حرف *, size_t);
ساكن صحيح	 g_lstat(Char *, بنية stat *, glob_t *);
ساكن DIR	*g_opendir(Char *, glob_t *);
ساكن Char	*g_strchr(ثابت Char *, صحيح);
ساكن صحيح	 g_strncmp(ثابت Char *, ثابت حرف *, size_t);
ساكن صحيح	 g_stat(Char *, بنية stat *, glob_t *);
ساكن صحيح	 glob0(ثابت Char *, glob_t *, بنية glob_lim *);
ساكن صحيح	 glob1(Char *, Char *, glob_t *, بنية glob_lim *);
ساكن صحيح	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, بنية glob_lim *);
ساكن صحيح	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, بنية glob_lim *);
ساكن صحيح	 globextend(ثابت Char *, glob_t *, بنية glob_lim *,
		    بنية stat *);
ساكن ثابت Char *
		 globtilde(ثابت Char *, Char *, size_t, glob_t *);
ساكن صحيح	 globexp1(ثابت Char *, glob_t *, بنية glob_lim *);
ساكن صحيح	 globexp2(ثابت Char *, ثابت Char *, glob_t *,
		    بنية glob_lim *);
ساكن صحيح	 match(Char *, Char *, Char *);
#ifdef DEBUG
ساكن فراغ	 qprintf(ثابت حرف *, Char *);
#endif

صحيح
glob(ثابت حرف *pattern, صحيح flags, صحيح (*errfunc)(ثابت حرف *, صحيح),
    glob_t *pglob)
{
	ثابت u_char *patnext;
	صحيح c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	بنية glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	إذا (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = عدم;
		pglob->gl_statv = عدم;
		إذا (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	إذا (strnlen(pattern, PATH_MAX) == PATH_MAX)
		إرجاع(GLOB_NOMATCH);

	إذا (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		إرجاع GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	إذا (flags & GLOB_NOESCAPE)
		بينما (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	وإلا {
		/* Protect the quoted characters. */
		بينما (bufnext < bufend && (c = *patnext++) != EOS)
			إذا (c == QUOTE) {
				إذا ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} وإلا
				*bufnext++ = c;
	}
	*bufnext = EOS;

	إذا (flags & GLOB_BRACE)
		إرجاع globexp1(patbuf, pglob, &limit);
	وإلا
		إرجاع glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
ساكن صحيح
globexp1(ثابت Char *pattern, glob_t *pglob, بنية glob_lim *limitp)
{
	ثابت Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	إذا (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		إرجاع glob0(pattern, pglob, limitp);

	إذا ((ptr = (ثابت Char *) g_strchr(ptr, LBRACE)) != عدم)
		إرجاع globexp2(ptr, pattern, pglob, limitp);

	إرجاع glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
ساكن صحيح
globexp2(ثابت Char *ptr, ثابت Char *pattern, glob_t *pglob,
    بنية glob_lim *limitp)
{
	صحيح     i, rv;
	Char   *lm, *ls;
	ثابت Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	لكل (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	لكل (i = 0, pe = ++ptr; *pe; pe++)
		إذا (*pe == LBRACKET) {
			/* Ignore everything between [] */
			لكل (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			إذا (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} وإلا إذا (*pe == LBRACE)
			i++;
		وإلا إذا (*pe == RBRACE) {
			إذا (i == 0)
				اكسر;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	إذا (i != 0 || *pe == EOS)
		إرجاع glob0(patbuf, pglob, limitp);

	لكل (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		بدل (*pm) {
		حالة LBRACKET:
			/* Ignore everything between [] */
			لكل (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			إذا (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			اكسر;

		حالة LBRACE:
			i++;
			اكسر;

		حالة RBRACE:
			إذا (i) {
				i--;
				اكسر;
			}
			/* FALLTHROUGH */
		حالة COMMA:
			إذا (i && *pm == COMMA)
				اكسر;
			وإلا {
				/* Append the current string */
				لكل (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				لكل (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				إذا (rv && rv != GLOB_NOMATCH)
					إرجاع rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			اكسر;

		افتراضي:
			اكسر;
		}
	}
	إرجاع 0;
}



/*
 * expand tilde from the passwd file.
 */
ساكن ثابت Char *
globtilde(ثابت Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	بنية passwd *pwd;
	حرف *h;
	ثابت Char *p;
	Char *b, *eb;

	إذا (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		إرجاع pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	لكل (p = pattern + 1, h = (حرف *) patbuf;
	    h < (حرف *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#إذا 0
	إذا (h == (حرف *)eb)
		إرجاع what;
#endif

	إذا (((حرف *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#إذا 0
		إذا (issetugid() != 0 || (h = getenv("HOME")) == عدم) {
#endif
		إذا ((getuid() != geteuid()) || (h = getenv("HOME")) == عدم) {
			إذا ((pwd = getpwuid(getuid())) == عدم)
				إرجاع pattern;
			وإلا
				h = pwd->pw_dir;
		}
	} وإلا {
		/*
		 * Expand a ~user
		 */
		إذا ((pwd = getpwnam((حرف*) patbuf)) == عدم)
			إرجاع pattern;
		وإلا
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	لكل (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	بينما (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	إرجاع patbuf;
}

ساكن صحيح
g_strncmp(ثابت Char *s1, ثابت حرف *s2, size_t n)
{
	صحيح rv = 0;

	بينما (n--) {
		rv = *(Char *)s1 - *(ثابت unsigned حرف *)s2++;
		إذا (rv)
			اكسر;
		إذا (*s1++ == '\0')
			اكسر;
	}
	إرجاع rv;
}

ساكن صحيح
g_charclass(ثابت Char **patternp, Char **bufnextp)
{
	ثابت Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	ثابت Char *colon;
	بنية cclass *cc;
	size_t len;

	إذا ((colon = g_strchr(pattern, ':')) == عدم || colon[1] != ']')
		إرجاع 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	لكل (cc = cclasses; cc->name != عدم; cc++) {
		إذا (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			اكسر;
	}
	إذا (cc->name == عدم)
		إرجاع -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	إرجاع 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
ساكن صحيح
glob0(ثابت Char *pattern, glob_t *pglob, بنية glob_lim *limitp)
{
	ثابت Char *qpatnext;
	صحيح c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	بينما ((c = *qpatnext++) != EOS) {
		بدل (c) {
		حالة LBRACKET:
			c = *qpatnext;
			إذا (c == NOT)
				++qpatnext;
			إذا (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == عدم) {
				*bufnext++ = LBRACKET;
				إذا (c == NOT)
					--qpatnext;
				اكسر;
			}
			*bufnext++ = M_SET;
			إذا (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			افعل {
				إذا (c == LBRACKET && *qpatnext == ':') {
					افعل {
						err = g_charclass(&qpatnext,
						    &bufnext);
						إذا (err)
							اكسر;
						c = *qpatnext++;
					} بينما (c == LBRACKET && *qpatnext == ':');
					إذا (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						إرجاع GLOB_NOMATCH;
					إذا (c == RBRACKET)
						اكسر;
				}
				*bufnext++ = CHAR(c);
				إذا (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} بينما ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			اكسر;
		حالة QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			اكسر;
		حالة STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			إذا (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			اكسر;
		افتراضي:
			*bufnext++ = CHAR(c);
			اكسر;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	إذا ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		إرجاع(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	إذا (pglob->gl_pathc == oldpathc) {
		إذا ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			إرجاع(globextend(pattern, pglob, limitp, عدم));
		وإلا
			إرجاع(GLOB_NOMATCH);
	}
	إذا (!(pglob->gl_flags & GLOB_NOSORT)) {
		إذا ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			بنية glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			إذا ((path_stat = calloc(n, حجم(*path_stat))) == عدم)
				إرجاع GLOB_NOSPACE;
			لكل (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, حجم(*path_stat), compare_gps);
			لكل (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			حرر(path_stat);
		} وإلا {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, حجم(حرف *),
			    compare);
		}
	}
	إرجاع(0);
}

ساكن صحيح
compare(ثابت فراغ *p, ثابت فراغ *q)
{
	إرجاع(strcmp(*(حرف **)p, *(حرف **)q));
}

ساكن صحيح
compare_gps(ثابت فراغ *_p, ثابت فراغ *_q)
{
	ثابت بنية glob_path_stat *p = (ثابت بنية glob_path_stat *)_p;
	ثابت بنية glob_path_stat *q = (ثابت بنية glob_path_stat *)_q;

	إرجاع(strcmp(p->gps_path, q->gps_path));
}

ساكن صحيح
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, بنية glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	إذا (*pattern == EOS)
		إرجاع(0);
	إرجاع(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
ساكن صحيح
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, بنية glob_lim *limitp)
{
	بنية stat sb;
	Char *p, *q;
	صحيح anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	لكل (anymeta = 0;;) {
		إذا (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			إذا ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				إرجاع(GLOB_NOSPACE);
			}
			إذا (g_lstat(pathbuf, &sb, pglob))
				إرجاع(0);

			إذا (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				إذا (pathend+1 > pathend_last)
					إرجاع (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			إرجاع(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		بينما (*p != EOS && *p != SEP) {
			إذا (ismeta(*p))
				anymeta = 1;
			إذا (q+1 > pathend_last)
				إرجاع (1);
			*q++ = *p++;
		}

		إذا (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			بينما (*pattern == SEP) {
				إذا (pathend+1 > pathend_last)
					إرجاع (1);
				*pathend++ = *pattern++;
			}
		} وإلا
			/* Need expansion, recurse. */
			إرجاع(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

ساكن صحيح
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    بنية glob_lim *limitp)
{
	بنية dirent *dp;
	DIR *dirp;
	صحيح err;
	حرف buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	بنية dirent *(*readdirfunc)(فراغ *);

	إذا (pathend > pathend_last)
		إرجاع (1);
	*pathend = EOS;
	errno = 0;

	إذا ((dirp = g_opendir(pathbuf, pglob)) == عدم) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		إذا (pglob->gl_errfunc) {
			إذا (g_Ctoc(pathbuf, buf, حجم(buf)))
				إرجاع(GLOB_ABORTED);
			إذا (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				إرجاع(GLOB_ABORTED);
		}
		إرجاع(0);
	}

	err = 0;

	/* Search directory for matching names. */
	إذا (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	وإلا
		readdirfunc = (بنية dirent *(*)(فراغ *))readdir;
	بينما ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		إذا ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			اكسر;
		}

		/* Initial DOT must be matched literally. */
		إذا (dp->d_name[0] == DOT && *pattern != DOT)
			استمر;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		بينما (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		إذا (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			اكسر;
		}

		إذا (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			استمر;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		إذا (err)
			اكسر;
	}

	إذا (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	وإلا
		closedir(dirp);
	إرجاع(err);
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
ساكن صحيح
globextend(ثابت Char *path, glob_t *pglob, بنية glob_lim *limitp,
    بنية stat *sb)
{
	حرف **pathv;
	size_t i, newn, len;
	حرف *copy = عدم;
	ثابت Char *p;
	بنية stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	إذا (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / حجم(*pathv) <= newn ||
	    SIZE_MAX / حجم(*statv) <= newn) {
 nospace:
		لكل (i = pglob->gl_offs; i < newn - 2; i++) {
			إذا (pglob->gl_pathv && pglob->gl_pathv[i])
				حرر(pglob->gl_pathv[i]);
			إذا ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				حرر(pglob->gl_statv[i]);
		}
		حرر(pglob->gl_pathv);
		pglob->gl_pathv = عدم;
		حرر(pglob->gl_statv);
		pglob->gl_statv = عدم;
		إرجاع(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, حجم(*pathv));
	إذا (pathv == عدم)
		اذهب nospace;
	إذا (pglob->gl_pathv == عدم && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		لكل (i = pglob->gl_offs; i > 0; i--)
			*--pathv = عدم;
	}
	pglob->gl_pathv = pathv;

	إذا ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, حجم(*statv));
		إذا (statv == عدم)
			اذهب nospace;
		إذا (pglob->gl_statv == عدم && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			لكل (i = pglob->gl_offs; i > 0; i--)
				*--statv = عدم;
		}
		pglob->gl_statv = statv;
		إذا (sb == عدم)
			statv[pglob->gl_offs + pglob->gl_pathc] = عدم;
		وإلا {
			limitp->glim_malloc += حجم(**statv);
			إذا ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				إرجاع(GLOB_NOSPACE);
			}
			إذا ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(حجم(**statv))) == عدم)
				اذهب copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    حجم(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = عدم;
	}

	لكل (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	إذا ((copy = malloc(len)) != عدم) {
		إذا (g_Ctoc(path, copy, len)) {
			حرر(copy);
			إرجاع(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = عدم;

	إذا ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * حجم(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		إرجاع(GLOB_NOSPACE);
	}
 copy_error:
	إرجاع(copy == عدم ? GLOB_NOSPACE : 0);
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
ساكن صحيح
match(Char *name, Char *pat, Char *patend)
{
	صحيح ok, negate_range;
	Char c, k;
	Char *nextp = عدم;
	Char *nextn = عدم;

loop:
	بينما (pat < patend) {
		c = *pat++;
		بدل (c & M_MASK) {
		حالة M_ALL:
			بينما (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			إذا (pat == patend)
				إرجاع(1);
			إذا (*name == EOS)
				إرجاع(0);
			nextn = name + 1;
			nextp = pat - 1;
			اكسر;
		حالة M_ONE:
			إذا (*name++ == EOS)
				اذهب fail;
			اكسر;
		حالة M_SET:
			ok = 0;
			إذا ((k = *name++) == EOS)
				اذهب fail;
			إذا ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			بينما (((c = *pat++) & M_MASK) != M_END) {
				إذا ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					إذا (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				إذا ((*pat & M_MASK) == M_RNG) {
					إذا (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} وإلا إذا (c == k)
					ok = 1;
			}
			إذا (ok == negate_range)
				اذهب fail;
			اكسر;
		افتراضي:
			إذا (*name++ != c)
				اذهب fail;
			اكسر;
		}
	}
	إذا (*name == EOS)
		إرجاع(1);

fail:
	إذا (nextn) {
		pat = nextp;
		name = nextn;
		اذهب loop;
	}
	إرجاع(0);
}

/* Free allocated data belonging to a glob_t structure. */
فراغ
globfree(glob_t *pglob)
{
	size_t i;
	حرف **pp;

	إذا (pglob->gl_pathv != عدم) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		لكل (i = pglob->gl_pathc; i--; ++pp)
			حرر(*pp);
		حرر(pglob->gl_pathv);
		pglob->gl_pathv = عدم;
	}
	إذا (pglob->gl_statv != عدم) {
		لكل (i = 0; i < pglob->gl_pathc; i++) {
			حرر(pglob->gl_statv[i]);
		}
		حرر(pglob->gl_statv);
		pglob->gl_statv = عدم;
	}
}

ساكن DIR *
g_opendir(Char *str, glob_t *pglob)
{
	حرف buf[PATH_MAX];

	إذا (!*str)
		strlcpy(buf, ".", حجم buf);
	وإلا {
		إذا (g_Ctoc(str, buf, حجم(buf)))
			إرجاع(عدم);
	}

	إذا (pglob->gl_flags & GLOB_ALTDIRFUNC)
		إرجاع((*pglob->gl_opendir)(buf));

	إرجاع(opendir(buf));
}

ساكن صحيح
g_lstat(Char *fn, بنية stat *sb, glob_t *pglob)
{
	حرف buf[PATH_MAX];

	إذا (g_Ctoc(fn, buf, حجم(buf)))
		إرجاع(-1);
	إذا (pglob->gl_flags & GLOB_ALTDIRFUNC)
		إرجاع((*pglob->gl_lstat)(buf, sb));
	إرجاع(lstat(buf, sb));
}

ساكن صحيح
g_stat(Char *fn, بنية stat *sb, glob_t *pglob)
{
	حرف buf[PATH_MAX];

	إذا (g_Ctoc(fn, buf, حجم(buf)))
		إرجاع(-1);
	إذا (pglob->gl_flags & GLOB_ALTDIRFUNC)
		إرجاع((*pglob->gl_stat)(buf, sb));
	إرجاع(stat(buf, sb));
}

ساكن Char *
g_strchr(ثابت Char *str, صحيح ch)
{
	افعل {
		إذا (*str == ch)
			إرجاع ((Char *)str);
	} بينما (*str++);
	إرجاع (عدم);
}

ساكن صحيح
g_Ctoc(ثابت Char *str, حرف *buf, size_t len)
{

	بينما (len--) {
		إذا ((*buf++ = *str++) == EOS)
			إرجاع (0);
	}
	إرجاع (1);
}

#ifdef DEBUG
ساكن فراغ
qprintf(ثابت حرف *str, Char *s)
{
	Char *p;

	(فراغ)printf("%s:\n", str);
	لكل (p = s; *p; p++)
		(فراغ)printf("%c", CHAR(*p));
	(فراغ)printf("\n");
	لكل (p = s; *p; p++)
		(فراغ)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(فراغ)printf("\n");
	لكل (p = s; *p; p++)
		(فراغ)printf("%c", ismeta(*p) ? '_' : ' ');
	(فراغ)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
