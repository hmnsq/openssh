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

#অন্তর্ভাব "includes.h"
#অন্তর্ভাব "glob.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>

#অন্তর্ভাব <dirent.h>
#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#যদি !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#অন্তর্ভাব "charclass.h"

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

প্রকারলেখ u_short Char;

#অন্যথা

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

প্রকারলেখ অক্ষর Char;

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

কাঠামো glob_lim {
	আকার_t	glim_malloc;
	আকার_t	glim_stat;
	আকার_t	glim_readdir;
};

কাঠামো glob_path_stat {
	অক্ষর		*gps_path;
	কাঠামো stat	*gps_stat;
};

স্থির পূর্ণসংখ্যা	 compare(ধ্রুবক শূন্য *, ধ্রুবক শূন্য *);
স্থির পূর্ণসংখ্যা	 compare_gps(ধ্রুবক শূন্য *, ধ্রুবক শূন্য *);
স্থির পূর্ণসংখ্যা	 g_Ctoc(ধ্রুবক Char *, অক্ষর *, আকার_t);
স্থির পূর্ণসংখ্যা	 g_lstat(Char *, কাঠামো stat *, glob_t *);
স্থির DIR	*g_opendir(Char *, glob_t *);
স্থির Char	*g_strchr(ধ্রুবক Char *, পূর্ণসংখ্যা);
স্থির পূর্ণসংখ্যা	 g_strncmp(ধ্রুবক Char *, ধ্রুবক অক্ষর *, আকার_t);
স্থির পূর্ণসংখ্যা	 g_stat(Char *, কাঠামো stat *, glob_t *);
স্থির পূর্ণসংখ্যা	 glob0(ধ্রুবক Char *, glob_t *, কাঠামো glob_lim *);
স্থির পূর্ণসংখ্যা	 glob1(Char *, Char *, glob_t *, কাঠামো glob_lim *);
স্থির পূর্ণসংখ্যা	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, কাঠামো glob_lim *);
স্থির পূর্ণসংখ্যা	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, কাঠামো glob_lim *);
স্থির পূর্ণসংখ্যা	 globextend(ধ্রুবক Char *, glob_t *, কাঠামো glob_lim *,
		    কাঠামো stat *);
স্থির ধ্রুবক Char *
		 globtilde(ধ্রুবক Char *, Char *, আকার_t, glob_t *);
স্থির পূর্ণসংখ্যা	 globexp1(ধ্রুবক Char *, glob_t *, কাঠামো glob_lim *);
স্থির পূর্ণসংখ্যা	 globexp2(ধ্রুবক Char *, ধ্রুবক Char *, glob_t *,
		    কাঠামো glob_lim *);
স্থির পূর্ণসংখ্যা	 match(Char *, Char *, Char *);
#ifdef DEBUG
স্থির শূন্য	 qprintf(ধ্রুবক অক্ষর *, Char *);
#endif

পূর্ণসংখ্যা
glob(ধ্রুবক অক্ষর *pattern, পূর্ণসংখ্যা flags, পূর্ণসংখ্যা (*errfunc)(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা),
    glob_t *pglob)
{
	ধ্রুবক u_char *patnext;
	পূর্ণসংখ্যা c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	কাঠামো glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	যদি (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = ফাঁকা;
		pglob->gl_statv = ফাঁকা;
		যদি (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	যদি (strnlen(pattern, PATH_MAX) == PATH_MAX)
		ফেরত(GLOB_NOMATCH);

	যদি (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		ফেরত GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	যদি (flags & GLOB_NOESCAPE)
		যখন (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	অন্যথা {
		/* Protect the quoted characters. */
		যখন (bufnext < bufend && (c = *patnext++) != EOS)
			যদি (c == QUOTE) {
				যদি ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} অন্যথা
				*bufnext++ = c;
	}
	*bufnext = EOS;

	যদি (flags & GLOB_BRACE)
		ফেরত globexp1(patbuf, pglob, &limit);
	অন্যথা
		ফেরত glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
স্থির পূর্ণসংখ্যা
globexp1(ধ্রুবক Char *pattern, glob_t *pglob, কাঠামো glob_lim *limitp)
{
	ধ্রুবক Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	যদি (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		ফেরত glob0(pattern, pglob, limitp);

	যদি ((ptr = (ধ্রুবক Char *) g_strchr(ptr, LBRACE)) != ফাঁকা)
		ফেরত globexp2(ptr, pattern, pglob, limitp);

	ফেরত glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
স্থির পূর্ণসংখ্যা
globexp2(ধ্রুবক Char *ptr, ধ্রুবক Char *pattern, glob_t *pglob,
    কাঠামো glob_lim *limitp)
{
	পূর্ণসংখ্যা     i, rv;
	Char   *lm, *ls;
	ধ্রুবক Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	জন্য (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	জন্য (i = 0, pe = ++ptr; *pe; pe++)
		যদি (*pe == LBRACKET) {
			/* Ignore everything between [] */
			জন্য (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			যদি (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} অন্যথা যদি (*pe == LBRACE)
			i++;
		অন্যথা যদি (*pe == RBRACE) {
			যদি (i == 0)
				বিরতি;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	যদি (i != 0 || *pe == EOS)
		ফেরত glob0(patbuf, pglob, limitp);

	জন্য (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		নির্বাচন (*pm) {
		ক্ষেত্র LBRACKET:
			/* Ignore everything between [] */
			জন্য (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			যদি (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			বিরতি;

		ক্ষেত্র LBRACE:
			i++;
			বিরতি;

		ক্ষেত্র RBRACE:
			যদি (i) {
				i--;
				বিরতি;
			}
			/* FALLTHROUGH */
		ক্ষেত্র COMMA:
			যদি (i && *pm == COMMA)
				বিরতি;
			অন্যথা {
				/* Append the current string */
				জন্য (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				জন্য (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				যদি (rv && rv != GLOB_NOMATCH)
					ফেরত rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			বিরতি;

		পূর্বনির্ধারিত:
			বিরতি;
		}
	}
	ফেরত 0;
}



/*
 * expand tilde from the passwd file.
 */
স্থির ধ্রুবক Char *
globtilde(ধ্রুবক Char *pattern, Char *patbuf, আকার_t patbuf_len, glob_t *pglob)
{
	কাঠামো passwd *pwd;
	অক্ষর *h;
	ধ্রুবক Char *p;
	Char *b, *eb;

	যদি (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		ফেরত pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	জন্য (p = pattern + 1, h = (অক্ষর *) patbuf;
	    h < (অক্ষর *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#যদি 0
	যদি (h == (অক্ষর *)eb)
		ফেরত what;
#endif

	যদি (((অক্ষর *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#যদি 0
		যদি (issetugid() != 0 || (h = getenv("HOME")) == ফাঁকা) {
#endif
		যদি ((getuid() != geteuid()) || (h = getenv("HOME")) == ফাঁকা) {
			যদি ((pwd = getpwuid(getuid())) == ফাঁকা)
				ফেরত pattern;
			অন্যথা
				h = pwd->pw_dir;
		}
	} অন্যথা {
		/*
		 * Expand a ~user
		 */
		যদি ((pwd = getpwnam((অক্ষর*) patbuf)) == ফাঁকা)
			ফেরত pattern;
		অন্যথা
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	জন্য (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	যখন (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	ফেরত patbuf;
}

স্থির পূর্ণসংখ্যা
g_strncmp(ধ্রুবক Char *s1, ধ্রুবক অক্ষর *s2, আকার_t n)
{
	পূর্ণসংখ্যা rv = 0;

	যখন (n--) {
		rv = *(Char *)s1 - *(ধ্রুবক unsigned অক্ষর *)s2++;
		যদি (rv)
			বিরতি;
		যদি (*s1++ == '\0')
			বিরতি;
	}
	ফেরত rv;
}

স্থির পূর্ণসংখ্যা
g_charclass(ধ্রুবক Char **patternp, Char **bufnextp)
{
	ধ্রুবক Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	ধ্রুবক Char *colon;
	কাঠামো cclass *cc;
	আকার_t len;

	যদি ((colon = g_strchr(pattern, ':')) == ফাঁকা || colon[1] != ']')
		ফেরত 1;	/* not a character class */

	len = (আকার_t)(colon - pattern);
	জন্য (cc = cclasses; cc->name != ফাঁকা; cc++) {
		যদি (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			বিরতি;
	}
	যদি (cc->name == ফাঁকা)
		ফেরত -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	ফেরত 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
স্থির পূর্ণসংখ্যা
glob0(ধ্রুবক Char *pattern, glob_t *pglob, কাঠামো glob_lim *limitp)
{
	ধ্রুবক Char *qpatnext;
	পূর্ণসংখ্যা c, err;
	আকার_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	যখন ((c = *qpatnext++) != EOS) {
		নির্বাচন (c) {
		ক্ষেত্র LBRACKET:
			c = *qpatnext;
			যদি (c == NOT)
				++qpatnext;
			যদি (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == ফাঁকা) {
				*bufnext++ = LBRACKET;
				যদি (c == NOT)
					--qpatnext;
				বিরতি;
			}
			*bufnext++ = M_SET;
			যদি (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			করো {
				যদি (c == LBRACKET && *qpatnext == ':') {
					করো {
						err = g_charclass(&qpatnext,
						    &bufnext);
						যদি (err)
							বিরতি;
						c = *qpatnext++;
					} যখন (c == LBRACKET && *qpatnext == ':');
					যদি (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						ফেরত GLOB_NOMATCH;
					যদি (c == RBRACKET)
						বিরতি;
				}
				*bufnext++ = CHAR(c);
				যদি (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} যখন ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			বিরতি;
		ক্ষেত্র QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			বিরতি;
		ক্ষেত্র STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			যদি (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			বিরতি;
		পূর্বনির্ধারিত:
			*bufnext++ = CHAR(c);
			বিরতি;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	যদি ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		ফেরত(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	যদি (pglob->gl_pathc == oldpathc) {
		যদি ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			ফেরত(globextend(pattern, pglob, limitp, ফাঁকা));
		অন্যথা
			ফেরত(GLOB_NOMATCH);
	}
	যদি (!(pglob->gl_flags & GLOB_NOSORT)) {
		যদি ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			কাঠামো glob_path_stat *path_stat;
			আকার_t i;
			আকার_t n = pglob->gl_pathc - oldpathc;
			আকার_t o = pglob->gl_offs + oldpathc;

			যদি ((path_stat = calloc(n, আকার(*path_stat))) == ফাঁকা)
				ফেরত GLOB_NOSPACE;
			জন্য (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, আকার(*path_stat), compare_gps);
			জন্য (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			মুক্ত(path_stat);
		} অন্যথা {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, আকার(অক্ষর *),
			    compare);
		}
	}
	ফেরত(0);
}

স্থির পূর্ণসংখ্যা
compare(ধ্রুবক শূন্য *p, ধ্রুবক শূন্য *q)
{
	ফেরত(strcmp(*(অক্ষর **)p, *(অক্ষর **)q));
}

স্থির পূর্ণসংখ্যা
compare_gps(ধ্রুবক শূন্য *_p, ধ্রুবক শূন্য *_q)
{
	ধ্রুবক কাঠামো glob_path_stat *p = (ধ্রুবক কাঠামো glob_path_stat *)_p;
	ধ্রুবক কাঠামো glob_path_stat *q = (ধ্রুবক কাঠামো glob_path_stat *)_q;

	ফেরত(strcmp(p->gps_path, q->gps_path));
}

স্থির পূর্ণসংখ্যা
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, কাঠামো glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	যদি (*pattern == EOS)
		ফেরত(0);
	ফেরত(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
স্থির পূর্ণসংখ্যা
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, কাঠামো glob_lim *limitp)
{
	কাঠামো stat sb;
	Char *p, *q;
	পূর্ণসংখ্যা anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	জন্য (anymeta = 0;;) {
		যদি (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			যদি ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				ফেরত(GLOB_NOSPACE);
			}
			যদি (g_lstat(pathbuf, &sb, pglob))
				ফেরত(0);

			যদি (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				যদি (pathend+1 > pathend_last)
					ফেরত (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			ফেরত(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		যখন (*p != EOS && *p != SEP) {
			যদি (ismeta(*p))
				anymeta = 1;
			যদি (q+1 > pathend_last)
				ফেরত (1);
			*q++ = *p++;
		}

		যদি (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			যখন (*pattern == SEP) {
				যদি (pathend+1 > pathend_last)
					ফেরত (1);
				*pathend++ = *pattern++;
			}
		} অন্যথা
			/* Need expansion, recurse. */
			ফেরত(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

স্থির পূর্ণসংখ্যা
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    কাঠামো glob_lim *limitp)
{
	কাঠামো dirent *dp;
	DIR *dirp;
	পূর্ণসংখ্যা err;
	অক্ষর buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	কাঠামো dirent *(*readdirfunc)(শূন্য *);

	যদি (pathend > pathend_last)
		ফেরত (1);
	*pathend = EOS;
	errno = 0;

	যদি ((dirp = g_opendir(pathbuf, pglob)) == ফাঁকা) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		যদি (pglob->gl_errfunc) {
			যদি (g_Ctoc(pathbuf, buf, আকার(buf)))
				ফেরত(GLOB_ABORTED);
			যদি (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				ফেরত(GLOB_ABORTED);
		}
		ফেরত(0);
	}

	err = 0;

	/* Search directory for matching names. */
	যদি (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	অন্যথা
		readdirfunc = (কাঠামো dirent *(*)(শূন্য *))readdir;
	যখন ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		যদি ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			বিরতি;
		}

		/* Initial DOT must be matched literally. */
		যদি (dp->d_name[0] == DOT && *pattern != DOT)
			চালু;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		যখন (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		যদি (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			বিরতি;
		}

		যদি (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			চালু;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		যদি (err)
			বিরতি;
	}

	যদি (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	অন্যথা
		closedir(dirp);
	ফেরত(err);
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
স্থির পূর্ণসংখ্যা
globextend(ধ্রুবক Char *path, glob_t *pglob, কাঠামো glob_lim *limitp,
    কাঠামো stat *sb)
{
	অক্ষর **pathv;
	আকার_t i, newn, len;
	অক্ষর *copy = ফাঁকা;
	ধ্রুবক Char *p;
	কাঠামো stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	যদি (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / আকার(*pathv) <= newn ||
	    SIZE_MAX / আকার(*statv) <= newn) {
 nospace:
		জন্য (i = pglob->gl_offs; i < newn - 2; i++) {
			যদি (pglob->gl_pathv && pglob->gl_pathv[i])
				মুক্ত(pglob->gl_pathv[i]);
			যদি ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				মুক্ত(pglob->gl_statv[i]);
		}
		মুক্ত(pglob->gl_pathv);
		pglob->gl_pathv = ফাঁকা;
		মুক্ত(pglob->gl_statv);
		pglob->gl_statv = ফাঁকা;
		ফেরত(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, আকার(*pathv));
	যদি (pathv == ফাঁকা)
		যাও nospace;
	যদি (pglob->gl_pathv == ফাঁকা && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		জন্য (i = pglob->gl_offs; i > 0; i--)
			*--pathv = ফাঁকা;
	}
	pglob->gl_pathv = pathv;

	যদি ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, আকার(*statv));
		যদি (statv == ফাঁকা)
			যাও nospace;
		যদি (pglob->gl_statv == ফাঁকা && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			জন্য (i = pglob->gl_offs; i > 0; i--)
				*--statv = ফাঁকা;
		}
		pglob->gl_statv = statv;
		যদি (sb == ফাঁকা)
			statv[pglob->gl_offs + pglob->gl_pathc] = ফাঁকা;
		অন্যথা {
			limitp->glim_malloc += আকার(**statv);
			যদি ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				ফেরত(GLOB_NOSPACE);
			}
			যদি ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(আকার(**statv))) == ফাঁকা)
				যাও copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    আকার(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = ফাঁকা;
	}

	জন্য (p = path; *p++;)
		;
	len = (আকার_t)(p - path);
	limitp->glim_malloc += len;
	যদি ((copy = malloc(len)) != ফাঁকা) {
		যদি (g_Ctoc(path, copy, len)) {
			মুক্ত(copy);
			ফেরত(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = ফাঁকা;

	যদি ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * আকার(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		ফেরত(GLOB_NOSPACE);
	}
 copy_error:
	ফেরত(copy == ফাঁকা ? GLOB_NOSPACE : 0);
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
স্থির পূর্ণসংখ্যা
match(Char *name, Char *pat, Char *patend)
{
	পূর্ণসংখ্যা ok, negate_range;
	Char c, k;
	Char *nextp = ফাঁকা;
	Char *nextn = ফাঁকা;

loop:
	যখন (pat < patend) {
		c = *pat++;
		নির্বাচন (c & M_MASK) {
		ক্ষেত্র M_ALL:
			যখন (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			যদি (pat == patend)
				ফেরত(1);
			যদি (*name == EOS)
				ফেরত(0);
			nextn = name + 1;
			nextp = pat - 1;
			বিরতি;
		ক্ষেত্র M_ONE:
			যদি (*name++ == EOS)
				যাও fail;
			বিরতি;
		ক্ষেত্র M_SET:
			ok = 0;
			যদি ((k = *name++) == EOS)
				যাও fail;
			যদি ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			যখন (((c = *pat++) & M_MASK) != M_END) {
				যদি ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					যদি (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				যদি ((*pat & M_MASK) == M_RNG) {
					যদি (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} অন্যথা যদি (c == k)
					ok = 1;
			}
			যদি (ok == negate_range)
				যাও fail;
			বিরতি;
		পূর্বনির্ধারিত:
			যদি (*name++ != c)
				যাও fail;
			বিরতি;
		}
	}
	যদি (*name == EOS)
		ফেরত(1);

fail:
	যদি (nextn) {
		pat = nextp;
		name = nextn;
		যাও loop;
	}
	ফেরত(0);
}

/* Free allocated data belonging to a glob_t structure. */
শূন্য
globfree(glob_t *pglob)
{
	আকার_t i;
	অক্ষর **pp;

	যদি (pglob->gl_pathv != ফাঁকা) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		জন্য (i = pglob->gl_pathc; i--; ++pp)
			মুক্ত(*pp);
		মুক্ত(pglob->gl_pathv);
		pglob->gl_pathv = ফাঁকা;
	}
	যদি (pglob->gl_statv != ফাঁকা) {
		জন্য (i = 0; i < pglob->gl_pathc; i++) {
			মুক্ত(pglob->gl_statv[i]);
		}
		মুক্ত(pglob->gl_statv);
		pglob->gl_statv = ফাঁকা;
	}
}

স্থির DIR *
g_opendir(Char *str, glob_t *pglob)
{
	অক্ষর buf[PATH_MAX];

	যদি (!*str)
		strlcpy(buf, ".", আকার buf);
	অন্যথা {
		যদি (g_Ctoc(str, buf, আকার(buf)))
			ফেরত(ফাঁকা);
	}

	যদি (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ফেরত((*pglob->gl_opendir)(buf));

	ফেরত(opendir(buf));
}

স্থির পূর্ণসংখ্যা
g_lstat(Char *fn, কাঠামো stat *sb, glob_t *pglob)
{
	অক্ষর buf[PATH_MAX];

	যদি (g_Ctoc(fn, buf, আকার(buf)))
		ফেরত(-1);
	যদি (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ফেরত((*pglob->gl_lstat)(buf, sb));
	ফেরত(lstat(buf, sb));
}

স্থির পূর্ণসংখ্যা
g_stat(Char *fn, কাঠামো stat *sb, glob_t *pglob)
{
	অক্ষর buf[PATH_MAX];

	যদি (g_Ctoc(fn, buf, আকার(buf)))
		ফেরত(-1);
	যদি (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ফেরত((*pglob->gl_stat)(buf, sb));
	ফেরত(stat(buf, sb));
}

স্থির Char *
g_strchr(ধ্রুবক Char *str, পূর্ণসংখ্যা ch)
{
	করো {
		যদি (*str == ch)
			ফেরত ((Char *)str);
	} যখন (*str++);
	ফেরত (ফাঁকা);
}

স্থির পূর্ণসংখ্যা
g_Ctoc(ধ্রুবক Char *str, অক্ষর *buf, আকার_t len)
{

	যখন (len--) {
		যদি ((*buf++ = *str++) == EOS)
			ফেরত (0);
	}
	ফেরত (1);
}

#ifdef DEBUG
স্থির শূন্য
qprintf(ধ্রুবক অক্ষর *str, Char *s)
{
	Char *p;

	(শূন্য)printf("%s:\n", str);
	জন্য (p = s; *p; p++)
		(শূন্য)printf("%c", CHAR(*p));
	(শূন্য)printf("\n");
	জন্য (p = s; *p; p++)
		(শূন্য)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(শূন্য)printf("\n");
	জন্য (p = s; *p; p++)
		(শূন্য)printf("%c", ismeta(*p) ? '_' : ' ');
	(শূন্য)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
