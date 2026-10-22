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

#که_تعریف_شوی TILDE
# undef TILDE
#د_که_پای

#تعریف_کړه	DOLLAR		'$'
#تعریف_کړه	DOT		'.'
#تعریف_کړه	EOS		'\0'
#تعریف_کړه	LBRACKET	'['
#تعریف_کړه	NOT		'!'
#تعریف_کړه	QUESTION	'?'
#تعریف_کړه	QUOTE		'\\'
#تعریف_کړه	RANGE		'-'
#تعریف_کړه	RBRACKET	']'
#تعریف_کړه	SEP		'/'
#تعریف_کړه	ستوری		'*'
#تعریف_کړه	TILDE		'~'
#تعریف_کړه	UNDERSCORE	'_'
#تعریف_کړه	LBRACE		'{'
#تعریف_کړه	RBRACE		'}'
#تعریف_کړه	SLASH		'/'
#تعریف_کړه	COMMA		','

#که_نه_تعریف_شوی DEBUG

#تعریف_کړه	M_QUOTE		0x8000
#تعریف_کړه	M_PROTECT	0x4000
#تعریف_کړه	M_ماسک		0xffff
#تعریف_کړه	M_ASCII		0x00ff

تعريفنوع u_short Char;

#وإلا

#تعریف_کړه	M_QUOTE		0x80
#تعریف_کړه	M_PROTECT	0x40
#تعریف_کړه	M_ماسک		0xff
#تعریف_کړه	M_ASCII		0x7f

تعريفنوع حرف Char;

#د_که_پای


#تعریف_کړه	CHAR(c)		((Char)((c)&M_ASCII))
#تعریف_کړه	META(c)		((Char)((c)|M_QUOTE))
#تعریف_کړه	M_ALL		META('*')
#تعریف_کړه	M_پای_ټکی		META(']')
#تعریف_کړه	M_NOT		META('!')
#تعریف_کړه	M_ONE		META('?')
#تعریف_کړه	M_RNG		META('-')
#تعریف_کړه	M_سېټ		META('[')
#تعریف_کړه	M_CLASS		META(':')
#تعریف_کړه	ismeta(c)	(((c)&M_QUOTE) != 0)

#تعریف_کړه	GLOB_حد_MALLOC	65536
#تعریف_کړه	GLOB_حد_STAT		2048
#تعریف_کړه	GLOB_حد_READDIR	16384

بنية glob_lim {
	اندازه_t	glim_malloc;
	اندازه_t	glim_stat;
	اندازه_t	glim_readdir;
};

بنية glob_لار_stat {
	حرف		*gps_لار;
	بنية stat	*gps_stat;
};

ساكن صحيح	 compare(ثابت فراغ *, ثابت فراغ *);
ساكن صحيح	 compare_gps(ثابت فراغ *, ثابت فراغ *);
ساكن صحيح	 g_Ctoc(ثابت Char *, حرف *, اندازه_t);
ساكن صحيح	 g_lstat(Char *, بنية stat *, glob_t *);
ساكن DIR	*g_opendir(Char *, glob_t *);
ساكن Char	*g_strchr(ثابت Char *, صحيح);
ساكن صحيح	 g_strncmp(ثابت Char *, ثابت حرف *, اندازه_t);
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
		 globtilde(ثابت Char *, Char *, اندازه_t, glob_t *);
ساكن صحيح	 globexp1(ثابت Char *, glob_t *, بنية glob_lim *);
ساكن صحيح	 globexp2(ثابت Char *, ثابت Char *, glob_t *,
		    بنية glob_lim *);
ساكن صحيح	 سمون(Char *, Char *, Char *);
#که_تعریف_شوی DEBUG
ساكن فراغ	 qprintf(ثابت حرف *, Char *);
#د_که_پای

صحيح
glob(ثابت حرف *نمونه, صحيح flags, صحيح (*errfunc)(ثابت حرف *, صحيح),
    glob_t *pglob)
{
	ثابت u_char *patnext;
	صحيح c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	بنية glob_lim حد = { 0, 0, 0 };

	patnext = (u_char *) نمونه;
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

	إذا (strnlen(نمونه, PATH_MAX) == PATH_MAX)
		أرجع(GLOB_NOMATCH);

	إذا (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		أرجع GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	إذا (flags & GLOB_NOESCAPE)
		طالما (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	وإلا {
		/* Protect the quoted characters. */
		طالما (bufnext < bufend && (c = *patnext++) != EOS)
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
		أرجع globexp1(patbuf, pglob, &حد);
	وإلا
		أرجع glob0(patbuf, pglob, &حد);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
ساكن صحيح
globexp1(ثابت Char *نمونه, glob_t *pglob, بنية glob_lim *limitp)
{
	ثابت Char* ptr = نمونه;

	/* Protect a single {}, for find(1), like csh */
	إذا (نمونه[0] == LBRACE && نمونه[1] == RBRACE && نمونه[2] == EOS)
		أرجع glob0(نمونه, pglob, limitp);

	إذا ((ptr = (ثابت Char *) g_strchr(ptr, LBRACE)) != عدم)
		أرجع globexp2(ptr, نمونه, pglob, limitp);

	أرجع glob0(نمونه, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
ساكن صحيح
globexp2(ثابت Char *ptr, ثابت Char *نمونه, glob_t *pglob,
    بنية glob_lim *limitp)
{
	صحيح     i, rv;
	Char   *lm, *ls;
	ثابت Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	لكل (lm = patbuf, pm = نمونه; pm != ptr; *lm++ = *pm++)
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
		أرجع glob0(patbuf, pglob, limitp);

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
#که_تعریف_شوی DEBUG
				qprintf("globexp2:", patbuf);
#د_که_پای
				rv = globexp1(patbuf, pglob, limitp);
				إذا (rv && rv != GLOB_NOMATCH)
					أرجع rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			اكسر;

		افتراضي:
			اكسر;
		}
	}
	أرجع 0;
}



/*
 * expand tilde from the passwd file.
 */
ساكن ثابت Char *
globtilde(ثابت Char *نمونه, Char *patbuf, اندازه_t patbuf_len, glob_t *pglob)
{
	بنية passwd *pwd;
	حرف *h;
	ثابت Char *p;
	Char *b, *eb;

	إذا (*نمونه != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		أرجع نمونه;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	لكل (p = نمونه + 1, h = (حرف *) patbuf;
	    h < (حرف *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#إذا 0
	إذا (h == (حرف *)eb)
		أرجع what;
#د_که_پای

	إذا (((حرف *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#إذا 0
		إذا (issetugid() != 0 || (h = getenv("HOME")) == عدم) {
#د_که_پای
		إذا ((getuid() != geteuid()) || (h = getenv("HOME")) == عدم) {
			إذا ((pwd = getpwuid(getuid())) == عدم)
				أرجع نمونه;
			وإلا
				h = pwd->pw_dir;
		}
	} وإلا {
		/*
		 * Expand a ~user
		 */
		إذا ((pwd = getpwnam((حرف*) patbuf)) == عدم)
			أرجع نمونه;
		وإلا
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	لكل (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	طالما (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	أرجع patbuf;
}

ساكن صحيح
g_strncmp(ثابت Char *s1, ثابت حرف *s2, اندازه_t n)
{
	صحيح rv = 0;

	طالما (n--) {
		rv = *(Char *)s1 - *(ثابت بینښه حرف *)s2++;
		إذا (rv)
			اكسر;
		إذا (*s1++ == '\0')
			اكسر;
	}
	أرجع rv;
}

ساكن صحيح
g_charclass(ثابت Char **patternp, Char **bufnextp)
{
	ثابت Char *نمونه = *patternp + 1;
	Char *bufnext = *bufnextp;
	ثابت Char *colon;
	بنية cclass *cc;
	اندازه_t len;

	إذا ((colon = g_strchr(نمونه, ':')) == عدم || colon[1] != ']')
		أرجع 1;	/* not a character class */

	len = (اندازه_t)(colon - نمونه);
	لكل (cc = cclasses; cc->name != عدم; cc++) {
		إذا (!g_strncmp(نمونه, cc->name, len) && cc->name[len] == '\0')
			اكسر;
	}
	إذا (cc->name == عدم)
		أرجع -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	أرجع 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
ساكن صحيح
glob0(ثابت Char *نمونه, glob_t *pglob, بنية glob_lim *limitp)
{
	ثابت Char *qpatnext;
	صحيح c, err;
	اندازه_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(نمونه, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	طالما ((c = *qpatnext++) != EOS) {
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
			*bufnext++ = M_سېټ;
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
					} طالما (c == LBRACKET && *qpatnext == ':');
					إذا (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						أرجع GLOB_NOMATCH;
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
			} طالما ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_پای_ټکی;
			اكسر;
		حالة QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			اكسر;
		حالة ستوری:
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
#که_تعریف_شوی DEBUG
	qprintf("glob0:", patbuf);
#د_که_پای

	إذا ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		أرجع(err);

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
			أرجع(globextend(نمونه, pglob, limitp, عدم));
		وإلا
			أرجع(GLOB_NOMATCH);
	}
	إذا (!(pglob->gl_flags & GLOB_NOSORT)) {
		إذا ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			بنية glob_لار_stat *لار_stat;
			اندازه_t i;
			اندازه_t n = pglob->gl_pathc - oldpathc;
			اندازه_t o = pglob->gl_offs + oldpathc;

			إذا ((لار_stat = حافظه_صفر_ورکړه(n, حجم(*لار_stat))) == عدم)
				أرجع GLOB_NOSPACE;
			لكل (i = 0; i < n; i++) {
				لار_stat[i].gps_لار = pglob->gl_pathv[o + i];
				لار_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(لار_stat, n, حجم(*لار_stat), compare_gps);
			لكل (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = لار_stat[i].gps_لار;
				pglob->gl_statv[o + i] = لار_stat[i].gps_stat;
			}
			حرر(لار_stat);
		} وإلا {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, حجم(حرف *),
			    compare);
		}
	}
	أرجع(0);
}

ساكن صحيح
compare(ثابت فراغ *p, ثابت فراغ *q)
{
	أرجع(strcmp(*(حرف **)p, *(حرف **)q));
}

ساكن صحيح
compare_gps(ثابت فراغ *_p, ثابت فراغ *_q)
{
	ثابت بنية glob_لار_stat *p = (ثابت بنية glob_لار_stat *)_p;
	ثابت بنية glob_لار_stat *q = (ثابت بنية glob_لار_stat *)_q;

	أرجع(strcmp(p->gps_لار, q->gps_لار));
}

ساكن صحيح
glob1(Char *نمونه, Char *نمونه_وروستی, glob_t *pglob, بنية glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	إذا (*نمونه == EOS)
		أرجع(0);
	أرجع(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    نمونه, نمونه_وروستی, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
ساكن صحيح
glob2(Char *pathbuf, Char *pathbuf_وروستی, Char *pathend, Char *pathend_وروستی,
    Char *نمونه, Char *نمونه_وروستی, glob_t *pglob, بنية glob_lim *limitp)
{
	بنية stat sb;
	Char *p, *q;
	صحيح anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	لكل (anymeta = 0;;) {
		إذا (*نمونه == EOS) {		/* End of pattern? */
			*pathend = EOS;

			إذا ((pglob->gl_flags & GLOB_حد) &&
			    limitp->glim_stat++ >= GLOB_حد_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				أرجع(GLOB_NOSPACE);
			}
			إذا (g_lstat(pathbuf, &sb, pglob))
				أرجع(0);

			إذا (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				إذا (pathend+1 > pathend_وروستی)
					أرجع (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			أرجع(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = نمونه;
		طالما (*p != EOS && *p != SEP) {
			إذا (ismeta(*p))
				anymeta = 1;
			إذا (q+1 > pathend_وروستی)
				أرجع (1);
			*q++ = *p++;
		}

		إذا (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			نمونه = p;
			طالما (*نمونه == SEP) {
				إذا (pathend+1 > pathend_وروستی)
					أرجع (1);
				*pathend++ = *نمونه++;
			}
		} وإلا
			/* Need expansion, recurse. */
			أرجع(glob3(pathbuf, pathbuf_وروستی, pathend,
			    pathend_وروستی, نمونه, p, نمونه_وروستی,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

ساكن صحيح
glob3(Char *pathbuf, Char *pathbuf_وروستی, Char *pathend, Char *pathend_وروستی,
    Char *نمونه, Char *restpattern, Char *restpattern_وروستی, glob_t *pglob,
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

	إذا (pathend > pathend_وروستی)
		أرجع (1);
	*pathend = EOS;
	errno = 0;

	إذا ((dirp = g_opendir(pathbuf, pglob)) == عدم) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		إذا (pglob->gl_errfunc) {
			إذا (g_Ctoc(pathbuf, buf, حجم(buf)))
				أرجع(GLOB_ABORTED);
			إذا (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				أرجع(GLOB_ABORTED);
		}
		أرجع(0);
	}

	err = 0;

	/* Search directory for matching names. */
	إذا (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	وإلا
		readdirfunc = (بنية dirent *(*)(فراغ *))readdir;
	طالما ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		إذا ((pglob->gl_flags & GLOB_حد) &&
		    limitp->glim_readdir++ >= GLOB_حد_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			اكسر;
		}

		/* Initial DOT must be matched literally. */
		إذا (dp->d_name[0] == DOT && *نمونه != DOT)
			استمر;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		طالما (dc < pathend_وروستی && (*dc++ = *sc++) != EOS)
			;
		إذا (dc >= pathend_وروستی) {
			*dc = EOS;
			err = 1;
			اكسر;
		}

		إذا (!سمون(pathend, نمونه, restpattern)) {
			*pathend = EOS;
			استمر;
		}
		err = glob2(pathbuf, pathbuf_وروستی, --dc, pathend_وروستی,
		    restpattern, restpattern_وروستی, pglob, limitp);
		إذا (err)
			اكسر;
	}

	إذا (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	وإلا
		closedir(dirp);
	أرجع(err);
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
globextend(ثابت Char *لار, glob_t *pglob, بنية glob_lim *limitp,
    بنية stat *sb)
{
	حرف **pathv;
	اندازه_t i, newn, len;
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
		أرجع(GLOB_NOSPACE);
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
			إذا ((pglob->gl_flags & GLOB_حد) &&
			    limitp->glim_malloc >= GLOB_حد_MALLOC) {
				errno = 0;
				أرجع(GLOB_NOSPACE);
			}
			إذا ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    حافظه_ورکړه(حجم(**statv))) == عدم)
				اذهب copy_error;
			حافظه_نقل(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    حجم(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = عدم;
	}

	لكل (p = لار; *p++;)
		;
	len = (اندازه_t)(p - لار);
	limitp->glim_malloc += len;
	إذا ((copy = حافظه_ورکړه(len)) != عدم) {
		إذا (g_Ctoc(لار, copy, len)) {
			حرر(copy);
			أرجع(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = عدم;

	إذا ((pglob->gl_flags & GLOB_حد) &&
	    (newn * حجم(*pathv)) + limitp->glim_malloc >
	    GLOB_حد_MALLOC) {
		errno = 0;
		أرجع(GLOB_NOSPACE);
	}
 copy_error:
	أرجع(copy == عدم ? GLOB_NOSPACE : 0);
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
سمون(Char *name, Char *pat, Char *patend)
{
	صحيح ok, negate_range;
	Char c, k;
	Char *nextp = عدم;
	Char *nextn = عدم;

loop:
	طالما (pat < patend) {
		c = *pat++;
		بدل (c & M_ماسک) {
		حالة M_ALL:
			طالما (pat < patend && (*pat & M_ماسک) == M_ALL)
				pat++;	/* eat consecutive '*' */
			إذا (pat == patend)
				أرجع(1);
			إذا (*name == EOS)
				أرجع(0);
			nextn = name + 1;
			nextp = pat - 1;
			اكسر;
		حالة M_ONE:
			إذا (*name++ == EOS)
				اذهب fail;
			اكسر;
		حالة M_سېټ:
			ok = 0;
			إذا ((k = *name++) == EOS)
				اذهب fail;
			إذا ((negate_range = ((*pat & M_ماسک) == M_NOT)) != EOS)
				++pat;
			طالما (((c = *pat++) & M_ماسک) != M_پای_ټکی) {
				إذا ((c & M_ماسک) == M_CLASS) {
					Char idx = *pat & M_ماسک;
					إذا (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				إذا ((*pat & M_ماسک) == M_RNG) {
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
		أرجع(1);

fail:
	إذا (nextn) {
		pat = nextp;
		name = nextn;
		اذهب loop;
	}
	أرجع(0);
}

/* Free allocated data belonging to a glob_t structure. */
فراغ
globfree(glob_t *pglob)
{
	اندازه_t i;
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
			أرجع(عدم);
	}

	إذا (pglob->gl_flags & GLOB_ALTDIRFUNC)
		أرجع((*pglob->gl_opendir)(buf));

	أرجع(opendir(buf));
}

ساكن صحيح
g_lstat(Char *fn, بنية stat *sb, glob_t *pglob)
{
	حرف buf[PATH_MAX];

	إذا (g_Ctoc(fn, buf, حجم(buf)))
		أرجع(-1);
	إذا (pglob->gl_flags & GLOB_ALTDIRFUNC)
		أرجع((*pglob->gl_lstat)(buf, sb));
	أرجع(lstat(buf, sb));
}

ساكن صحيح
g_stat(Char *fn, بنية stat *sb, glob_t *pglob)
{
	حرف buf[PATH_MAX];

	إذا (g_Ctoc(fn, buf, حجم(buf)))
		أرجع(-1);
	إذا (pglob->gl_flags & GLOB_ALTDIRFUNC)
		أرجع((*pglob->gl_stat)(buf, sb));
	أرجع(stat(buf, sb));
}

ساكن Char *
g_strchr(ثابت Char *str, صحيح ch)
{
	افعل {
		إذا (*str == ch)
			أرجع ((Char *)str);
	} طالما (*str++);
	أرجع (عدم);
}

ساكن صحيح
g_Ctoc(ثابت Char *str, حرف *buf, اندازه_t len)
{

	طالما (len--) {
		إذا ((*buf++ = *str++) == EOS)
			أرجع (0);
	}
	أرجع (1);
}

#که_تعریف_شوی DEBUG
ساكن فراغ
qprintf(ثابت حرف *str, Char *s)
{
	Char *p;

	(فراغ)چاپ_کړه("%s:\n", str);
	لكل (p = s; *p; p++)
		(فراغ)چاپ_کړه("%c", CHAR(*p));
	(فراغ)چاپ_کړه("\n");
	لكل (p = s; *p; p++)
		(فراغ)چاپ_کړه("%c", *p & M_PROTECT ? '"' : ' ');
	(فراغ)چاپ_کړه("\n");
	لكل (p = s; *p; p++)
		(فراغ)چاپ_کړه("%c", ismeta(*p) ? '_' : ' ');
	(فراغ)چاپ_کړه("\n");
}
#د_که_پای

#د_که_پای /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
