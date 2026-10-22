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

#اگر_تعریف_شدہ TILDE
# undef TILDE
#اگر_ختم

#تعریف_کرو	DOLLAR		'$'
#تعریف_کرو	DOT		'.'
#تعریف_کرو	EOS		'\0'
#تعریف_کرو	LBRACKET	'['
#تعریف_کرو	NOT		'!'
#تعریف_کرو	QUESTION	'?'
#تعریف_کرو	QUOTE		'\\'
#تعریف_کرو	RANGE		'-'
#تعریف_کرو	RBRACKET	']'
#تعریف_کرو	SEP		'/'
#تعریف_کرو	ستارہ		'*'
#تعریف_کرو	TILDE		'~'
#تعریف_کرو	UNDERSCORE	'_'
#تعریف_کرو	LBRACE		'{'
#تعریف_کرو	RBRACE		'}'
#تعریف_کرو	SLASH		'/'
#تعریف_کرو	COMMA		','

#اگر_غیر_تعریف_شدہ DEBUG

#تعریف_کرو	M_QUOTE		0x8000
#تعریف_کرو	M_PROTECT	0x4000
#تعریف_کرو	M_نقاب		0xffff
#تعریف_کرو	M_ASCII		0x00ff

قسمتعریف u_short Char;

#ورنہ

#تعریف_کرو	M_QUOTE		0x80
#تعریف_کرو	M_PROTECT	0x40
#تعریف_کرو	M_نقاب		0xff
#تعریف_کرو	M_ASCII		0x7f

قسمتعریف حرف Char;

#اگر_ختم


#تعریف_کرو	CHAR(c)		((Char)((c)&M_ASCII))
#تعریف_کرو	META(c)		((Char)((c)|M_QUOTE))
#تعریف_کرو	M_ALL		META('*')
#تعریف_کرو	M_انتہا		META(']')
#تعریف_کرو	M_NOT		META('!')
#تعریف_کرو	M_ONE		META('?')
#تعریف_کرو	M_RNG		META('-')
#تعریف_کرو	M_سیٹ		META('[')
#تعریف_کرو	M_CLASS		META(':')
#تعریف_کرو	ismeta(c)	(((c)&M_QUOTE) != 0)

#تعریف_کرو	GLOB_حد_بندی_MALLOC	65536
#تعریف_کرو	GLOB_حد_بندی_STAT		2048
#تعریف_کرو	GLOB_حد_بندی_READDIR	16384

ساخت glob_lim {
	سائز_t	glim_malloc;
	سائز_t	glim_stat;
	سائز_t	glim_readdir;
};

ساخت glob_راستہ_stat {
	حرف		*gps_راستہ;
	ساخت stat	*gps_stat;
};

ساکن صحیح	 compare(ثابت خالی *, ثابت خالی *);
ساکن صحیح	 compare_gps(ثابت خالی *, ثابت خالی *);
ساکن صحیح	 g_Ctoc(ثابت Char *, حرف *, سائز_t);
ساکن صحیح	 g_lstat(Char *, ساخت stat *, glob_t *);
ساکن DIR	*g_opendir(Char *, glob_t *);
ساکن Char	*g_strchr(ثابت Char *, صحیح);
ساکن صحیح	 g_strncmp(ثابت Char *, ثابت حرف *, سائز_t);
ساکن صحیح	 g_stat(Char *, ساخت stat *, glob_t *);
ساکن صحیح	 glob0(ثابت Char *, glob_t *, ساخت glob_lim *);
ساکن صحیح	 glob1(Char *, Char *, glob_t *, ساخت glob_lim *);
ساکن صحیح	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, ساخت glob_lim *);
ساکن صحیح	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, ساخت glob_lim *);
ساکن صحیح	 globextend(ثابت Char *, glob_t *, ساخت glob_lim *,
		    ساخت stat *);
ساکن ثابت Char *
		 globtilde(ثابت Char *, Char *, سائز_t, glob_t *);
ساکن صحیح	 globexp1(ثابت Char *, glob_t *, ساخت glob_lim *);
ساکن صحیح	 globexp2(ثابت Char *, ثابت Char *, glob_t *,
		    ساخت glob_lim *);
ساکن صحیح	 مطابقت(Char *, Char *, Char *);
#اگر_تعریف_شدہ DEBUG
ساکن خالی	 qprintf(ثابت حرف *, Char *);
#اگر_ختم

صحیح
glob(ثابت حرف *نمونہ, صحیح flags, صحیح (*errfunc)(ثابت حرف *, صحیح),
    glob_t *pglob)
{
	ثابت u_char *patnext;
	صحیح c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	ساخت glob_lim حد_بندی = { 0, 0, 0 };

	patnext = (u_char *) نمونہ;
	اگر (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = تہی;
		pglob->gl_statv = تہی;
		اگر (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	اگر (strnlen(نمونہ, PATH_MAX) == PATH_MAX)
		واپس(GLOB_NOMATCH);

	اگر (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		واپس GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	اگر (flags & GLOB_NOESCAPE)
		جب (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	ورنہ {
		/* Protect the quoted characters. */
		جب (bufnext < bufend && (c = *patnext++) != EOS)
			اگر (c == QUOTE) {
				اگر ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} ورنہ
				*bufnext++ = c;
	}
	*bufnext = EOS;

	اگر (flags & GLOB_BRACE)
		واپس globexp1(patbuf, pglob, &حد_بندی);
	ورنہ
		واپس glob0(patbuf, pglob, &حد_بندی);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
ساکن صحیح
globexp1(ثابت Char *نمونہ, glob_t *pglob, ساخت glob_lim *limitp)
{
	ثابت Char* ptr = نمونہ;

	/* Protect a single {}, for find(1), like csh */
	اگر (نمونہ[0] == LBRACE && نمونہ[1] == RBRACE && نمونہ[2] == EOS)
		واپس glob0(نمونہ, pglob, limitp);

	اگر ((ptr = (ثابت Char *) g_strchr(ptr, LBRACE)) != تہی)
		واپس globexp2(ptr, نمونہ, pglob, limitp);

	واپس glob0(نمونہ, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
ساکن صحیح
globexp2(ثابت Char *ptr, ثابت Char *نمونہ, glob_t *pglob,
    ساخت glob_lim *limitp)
{
	صحیح     i, rv;
	Char   *lm, *ls;
	ثابت Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	برائے (lm = patbuf, pm = نمونہ; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	برائے (i = 0, pe = ++ptr; *pe; pe++)
		اگر (*pe == LBRACKET) {
			/* Ignore everything between [] */
			برائے (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			اگر (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} ورنہ اگر (*pe == LBRACE)
			i++;
		ورنہ اگر (*pe == RBRACE) {
			اگر (i == 0)
				توڑو;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	اگر (i != 0 || *pe == EOS)
		واپس glob0(patbuf, pglob, limitp);

	برائے (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		انتخاب (*pm) {
		حالت LBRACKET:
			/* Ignore everything between [] */
			برائے (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			اگر (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			توڑو;

		حالت LBRACE:
			i++;
			توڑو;

		حالت RBRACE:
			اگر (i) {
				i--;
				توڑو;
			}
			/* FALLTHROUGH */
		حالت COMMA:
			اگر (i && *pm == COMMA)
				توڑو;
			ورنہ {
				/* Append the current string */
				برائے (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				برائے (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#اگر_تعریف_شدہ DEBUG
				qprintf("globexp2:", patbuf);
#اگر_ختم
				rv = globexp1(patbuf, pglob, limitp);
				اگر (rv && rv != GLOB_NOMATCH)
					واپس rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			توڑو;

		طےشدہ:
			توڑو;
		}
	}
	واپس 0;
}



/*
 * expand tilde from the passwd file.
 */
ساکن ثابت Char *
globtilde(ثابت Char *نمونہ, Char *patbuf, سائز_t patbuf_len, glob_t *pglob)
{
	ساخت passwd *pwd;
	حرف *h;
	ثابت Char *p;
	Char *b, *eb;

	اگر (*نمونہ != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		واپس نمونہ;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	برائے (p = نمونہ + 1, h = (حرف *) patbuf;
	    h < (حرف *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#اگر 0
	اگر (h == (حرف *)eb)
		واپس what;
#اگر_ختم

	اگر (((حرف *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#اگر 0
		اگر (issetugid() != 0 || (h = getenv("HOME")) == تہی) {
#اگر_ختم
		اگر ((getuid() != geteuid()) || (h = getenv("HOME")) == تہی) {
			اگر ((pwd = getpwuid(getuid())) == تہی)
				واپس نمونہ;
			ورنہ
				h = pwd->pw_dir;
		}
	} ورنہ {
		/*
		 * Expand a ~user
		 */
		اگر ((pwd = getpwnam((حرف*) patbuf)) == تہی)
			واپس نمونہ;
		ورنہ
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	برائے (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	جب (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	واپس patbuf;
}

ساکن صحیح
g_strncmp(ثابت Char *s1, ثابت حرف *s2, سائز_t n)
{
	صحیح rv = 0;

	جب (n--) {
		rv = *(Char *)s1 - *(ثابت غیرعلامتی حرف *)s2++;
		اگر (rv)
			توڑو;
		اگر (*s1++ == '\0')
			توڑو;
	}
	واپس rv;
}

ساکن صحیح
g_charclass(ثابت Char **patternp, Char **bufnextp)
{
	ثابت Char *نمونہ = *patternp + 1;
	Char *bufnext = *bufnextp;
	ثابت Char *colon;
	ساخت cclass *cc;
	سائز_t len;

	اگر ((colon = g_strchr(نمونہ, ':')) == تہی || colon[1] != ']')
		واپس 1;	/* not a character class */

	len = (سائز_t)(colon - نمونہ);
	برائے (cc = cclasses; cc->name != تہی; cc++) {
		اگر (!g_strncmp(نمونہ, cc->name, len) && cc->name[len] == '\0')
			توڑو;
	}
	اگر (cc->name == تہی)
		واپس -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	واپس 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
ساکن صحیح
glob0(ثابت Char *نمونہ, glob_t *pglob, ساخت glob_lim *limitp)
{
	ثابت Char *qpatnext;
	صحیح c, err;
	سائز_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(نمونہ, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	جب ((c = *qpatnext++) != EOS) {
		انتخاب (c) {
		حالت LBRACKET:
			c = *qpatnext;
			اگر (c == NOT)
				++qpatnext;
			اگر (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == تہی) {
				*bufnext++ = LBRACKET;
				اگر (c == NOT)
					--qpatnext;
				توڑو;
			}
			*bufnext++ = M_سیٹ;
			اگر (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			کرو {
				اگر (c == LBRACKET && *qpatnext == ':') {
					کرو {
						err = g_charclass(&qpatnext,
						    &bufnext);
						اگر (err)
							توڑو;
						c = *qpatnext++;
					} جب (c == LBRACKET && *qpatnext == ':');
					اگر (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						واپس GLOB_NOMATCH;
					اگر (c == RBRACKET)
						توڑو;
				}
				*bufnext++ = CHAR(c);
				اگر (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} جب ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_انتہا;
			توڑو;
		حالت QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			توڑو;
		حالت ستارہ:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			اگر (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			توڑو;
		طےشدہ:
			*bufnext++ = CHAR(c);
			توڑو;
		}
	}
	*bufnext = EOS;
#اگر_تعریف_شدہ DEBUG
	qprintf("glob0:", patbuf);
#اگر_ختم

	اگر ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		واپس(err);

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
			واپس(globextend(نمونہ, pglob, limitp, تہی));
		ورنہ
			واپس(GLOB_NOMATCH);
	}
	اگر (!(pglob->gl_flags & GLOB_NOSORT)) {
		اگر ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			ساخت glob_راستہ_stat *راستہ_stat;
			سائز_t i;
			سائز_t n = pglob->gl_pathc - oldpathc;
			سائز_t o = pglob->gl_offs + oldpathc;

			اگر ((راستہ_stat = صفر_حافظہ_دو(n, حجم(*راستہ_stat))) == تہی)
				واپس GLOB_NOSPACE;
			برائے (i = 0; i < n; i++) {
				راستہ_stat[i].gps_راستہ = pglob->gl_pathv[o + i];
				راستہ_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(راستہ_stat, n, حجم(*راستہ_stat), compare_gps);
			برائے (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = راستہ_stat[i].gps_راستہ;
				pglob->gl_statv[o + i] = راستہ_stat[i].gps_stat;
			}
			آزاد(راستہ_stat);
		} ورنہ {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, حجم(حرف *),
			    compare);
		}
	}
	واپس(0);
}

ساکن صحیح
compare(ثابت خالی *p, ثابت خالی *q)
{
	واپس(strcmp(*(حرف **)p, *(حرف **)q));
}

ساکن صحیح
compare_gps(ثابت خالی *_p, ثابت خالی *_q)
{
	ثابت ساخت glob_راستہ_stat *p = (ثابت ساخت glob_راستہ_stat *)_p;
	ثابت ساخت glob_راستہ_stat *q = (ثابت ساخت glob_راستہ_stat *)_q;

	واپس(strcmp(p->gps_راستہ, q->gps_راستہ));
}

ساکن صحیح
glob1(Char *نمونہ, Char *نمونہ_آخری, glob_t *pglob, ساخت glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	اگر (*نمونہ == EOS)
		واپس(0);
	واپس(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    نمونہ, نمونہ_آخری, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
ساکن صحیح
glob2(Char *pathbuf, Char *pathbuf_آخری, Char *pathend, Char *pathend_آخری,
    Char *نمونہ, Char *نمونہ_آخری, glob_t *pglob, ساخت glob_lim *limitp)
{
	ساخت stat sb;
	Char *p, *q;
	صحیح anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	برائے (anymeta = 0;;) {
		اگر (*نمونہ == EOS) {		/* End of pattern? */
			*pathend = EOS;

			اگر ((pglob->gl_flags & GLOB_حد_بندی) &&
			    limitp->glim_stat++ >= GLOB_حد_بندی_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				واپس(GLOB_NOSPACE);
			}
			اگر (g_lstat(pathbuf, &sb, pglob))
				واپس(0);

			اگر (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				اگر (pathend+1 > pathend_آخری)
					واپس (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			واپس(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = نمونہ;
		جب (*p != EOS && *p != SEP) {
			اگر (ismeta(*p))
				anymeta = 1;
			اگر (q+1 > pathend_آخری)
				واپس (1);
			*q++ = *p++;
		}

		اگر (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			نمونہ = p;
			جب (*نمونہ == SEP) {
				اگر (pathend+1 > pathend_آخری)
					واپس (1);
				*pathend++ = *نمونہ++;
			}
		} ورنہ
			/* Need expansion, recurse. */
			واپس(glob3(pathbuf, pathbuf_آخری, pathend,
			    pathend_آخری, نمونہ, p, نمونہ_آخری,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

ساکن صحیح
glob3(Char *pathbuf, Char *pathbuf_آخری, Char *pathend, Char *pathend_آخری,
    Char *نمونہ, Char *restpattern, Char *restpattern_آخری, glob_t *pglob,
    ساخت glob_lim *limitp)
{
	ساخت dirent *dp;
	DIR *dirp;
	صحیح err;
	حرف buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	ساخت dirent *(*readdirfunc)(خالی *);

	اگر (pathend > pathend_آخری)
		واپس (1);
	*pathend = EOS;
	errno = 0;

	اگر ((dirp = g_opendir(pathbuf, pglob)) == تہی) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		اگر (pglob->gl_errfunc) {
			اگر (g_Ctoc(pathbuf, buf, حجم(buf)))
				واپس(GLOB_ABORTED);
			اگر (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				واپس(GLOB_ABORTED);
		}
		واپس(0);
	}

	err = 0;

	/* Search directory for matching names. */
	اگر (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	ورنہ
		readdirfunc = (ساخت dirent *(*)(خالی *))readdir;
	جب ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		اگر ((pglob->gl_flags & GLOB_حد_بندی) &&
		    limitp->glim_readdir++ >= GLOB_حد_بندی_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			توڑو;
		}

		/* Initial DOT must be matched literally. */
		اگر (dp->d_name[0] == DOT && *نمونہ != DOT)
			جاری;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		جب (dc < pathend_آخری && (*dc++ = *sc++) != EOS)
			;
		اگر (dc >= pathend_آخری) {
			*dc = EOS;
			err = 1;
			توڑو;
		}

		اگر (!مطابقت(pathend, نمونہ, restpattern)) {
			*pathend = EOS;
			جاری;
		}
		err = glob2(pathbuf, pathbuf_آخری, --dc, pathend_آخری,
		    restpattern, restpattern_آخری, pglob, limitp);
		اگر (err)
			توڑو;
	}

	اگر (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	ورنہ
		closedir(dirp);
	واپس(err);
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
ساکن صحیح
globextend(ثابت Char *راستہ, glob_t *pglob, ساخت glob_lim *limitp,
    ساخت stat *sb)
{
	حرف **pathv;
	سائز_t i, newn, len;
	حرف *copy = تہی;
	ثابت Char *p;
	ساخت stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	اگر (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / حجم(*pathv) <= newn ||
	    SIZE_MAX / حجم(*statv) <= newn) {
 nospace:
		برائے (i = pglob->gl_offs; i < newn - 2; i++) {
			اگر (pglob->gl_pathv && pglob->gl_pathv[i])
				آزاد(pglob->gl_pathv[i]);
			اگر ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				آزاد(pglob->gl_statv[i]);
		}
		آزاد(pglob->gl_pathv);
		pglob->gl_pathv = تہی;
		آزاد(pglob->gl_statv);
		pglob->gl_statv = تہی;
		واپس(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, حجم(*pathv));
	اگر (pathv == تہی)
		جاؤ nospace;
	اگر (pglob->gl_pathv == تہی && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		برائے (i = pglob->gl_offs; i > 0; i--)
			*--pathv = تہی;
	}
	pglob->gl_pathv = pathv;

	اگر ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, حجم(*statv));
		اگر (statv == تہی)
			جاؤ nospace;
		اگر (pglob->gl_statv == تہی && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			برائے (i = pglob->gl_offs; i > 0; i--)
				*--statv = تہی;
		}
		pglob->gl_statv = statv;
		اگر (sb == تہی)
			statv[pglob->gl_offs + pglob->gl_pathc] = تہی;
		ورنہ {
			limitp->glim_malloc += حجم(**statv);
			اگر ((pglob->gl_flags & GLOB_حد_بندی) &&
			    limitp->glim_malloc >= GLOB_حد_بندی_MALLOC) {
				errno = 0;
				واپس(GLOB_NOSPACE);
			}
			اگر ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    حافظہ_دو(حجم(**statv))) == تہی)
				جاؤ copy_error;
			حافظہ_نقل(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    حجم(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = تہی;
	}

	برائے (p = راستہ; *p++;)
		;
	len = (سائز_t)(p - راستہ);
	limitp->glim_malloc += len;
	اگر ((copy = حافظہ_دو(len)) != تہی) {
		اگر (g_Ctoc(راستہ, copy, len)) {
			آزاد(copy);
			واپس(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = تہی;

	اگر ((pglob->gl_flags & GLOB_حد_بندی) &&
	    (newn * حجم(*pathv)) + limitp->glim_malloc >
	    GLOB_حد_بندی_MALLOC) {
		errno = 0;
		واپس(GLOB_NOSPACE);
	}
 copy_error:
	واپس(copy == تہی ? GLOB_NOSPACE : 0);
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
ساکن صحیح
مطابقت(Char *name, Char *pat, Char *patend)
{
	صحیح ok, negate_range;
	Char c, k;
	Char *nextp = تہی;
	Char *nextn = تہی;

loop:
	جب (pat < patend) {
		c = *pat++;
		انتخاب (c & M_نقاب) {
		حالت M_ALL:
			جب (pat < patend && (*pat & M_نقاب) == M_ALL)
				pat++;	/* eat consecutive '*' */
			اگر (pat == patend)
				واپس(1);
			اگر (*name == EOS)
				واپس(0);
			nextn = name + 1;
			nextp = pat - 1;
			توڑو;
		حالت M_ONE:
			اگر (*name++ == EOS)
				جاؤ fail;
			توڑو;
		حالت M_سیٹ:
			ok = 0;
			اگر ((k = *name++) == EOS)
				جاؤ fail;
			اگر ((negate_range = ((*pat & M_نقاب) == M_NOT)) != EOS)
				++pat;
			جب (((c = *pat++) & M_نقاب) != M_انتہا) {
				اگر ((c & M_نقاب) == M_CLASS) {
					Char idx = *pat & M_نقاب;
					اگر (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				اگر ((*pat & M_نقاب) == M_RNG) {
					اگر (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} ورنہ اگر (c == k)
					ok = 1;
			}
			اگر (ok == negate_range)
				جاؤ fail;
			توڑو;
		طےشدہ:
			اگر (*name++ != c)
				جاؤ fail;
			توڑو;
		}
	}
	اگر (*name == EOS)
		واپس(1);

fail:
	اگر (nextn) {
		pat = nextp;
		name = nextn;
		جاؤ loop;
	}
	واپس(0);
}

/* Free allocated data belonging to a glob_t structure. */
خالی
globfree(glob_t *pglob)
{
	سائز_t i;
	حرف **pp;

	اگر (pglob->gl_pathv != تہی) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		برائے (i = pglob->gl_pathc; i--; ++pp)
			آزاد(*pp);
		آزاد(pglob->gl_pathv);
		pglob->gl_pathv = تہی;
	}
	اگر (pglob->gl_statv != تہی) {
		برائے (i = 0; i < pglob->gl_pathc; i++) {
			آزاد(pglob->gl_statv[i]);
		}
		آزاد(pglob->gl_statv);
		pglob->gl_statv = تہی;
	}
}

ساکن DIR *
g_opendir(Char *str, glob_t *pglob)
{
	حرف buf[PATH_MAX];

	اگر (!*str)
		strlcpy(buf, ".", حجم buf);
	ورنہ {
		اگر (g_Ctoc(str, buf, حجم(buf)))
			واپس(تہی);
	}

	اگر (pglob->gl_flags & GLOB_ALTDIRFUNC)
		واپس((*pglob->gl_opendir)(buf));

	واپس(opendir(buf));
}

ساکن صحیح
g_lstat(Char *fn, ساخت stat *sb, glob_t *pglob)
{
	حرف buf[PATH_MAX];

	اگر (g_Ctoc(fn, buf, حجم(buf)))
		واپس(-1);
	اگر (pglob->gl_flags & GLOB_ALTDIRFUNC)
		واپس((*pglob->gl_lstat)(buf, sb));
	واپس(lstat(buf, sb));
}

ساکن صحیح
g_stat(Char *fn, ساخت stat *sb, glob_t *pglob)
{
	حرف buf[PATH_MAX];

	اگر (g_Ctoc(fn, buf, حجم(buf)))
		واپس(-1);
	اگر (pglob->gl_flags & GLOB_ALTDIRFUNC)
		واپس((*pglob->gl_stat)(buf, sb));
	واپس(stat(buf, sb));
}

ساکن Char *
g_strchr(ثابت Char *str, صحیح ch)
{
	کرو {
		اگر (*str == ch)
			واپس ((Char *)str);
	} جب (*str++);
	واپس (تہی);
}

ساکن صحیح
g_Ctoc(ثابت Char *str, حرف *buf, سائز_t len)
{

	جب (len--) {
		اگر ((*buf++ = *str++) == EOS)
			واپس (0);
	}
	واپس (1);
}

#اگر_تعریف_شدہ DEBUG
ساکن خالی
qprintf(ثابت حرف *str, Char *s)
{
	Char *p;

	(خالی)لکھو("%s:\n", str);
	برائے (p = s; *p; p++)
		(خالی)لکھو("%c", CHAR(*p));
	(خالی)لکھو("\n");
	برائے (p = s; *p; p++)
		(خالی)لکھو("%c", *p & M_PROTECT ? '"' : ' ');
	(خالی)لکھو("\n");
	برائے (p = s; *p; p++)
		(خالی)لکھو("%c", ismeta(*p) ? '_' : ' ');
	(خالی)لکھو("\n");
}
#اگر_ختم

#اگر_ختم /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
