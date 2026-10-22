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

#অন্তর্ভাৱ "includes.h"
#অন্তর্ভাৱ "glob.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>

#অন্তর্ভাৱ <dirent.h>
#অন্তর্ভাৱ <ctype.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>

#যদি !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#অন্তর্ভাৱ "charclass.h"

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

প্রকারনির্দেশ u_short Char;

#অন্যথা

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

প্রকারনির্দেশ ৱর্ণ Char;

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

সংরচনা glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

সংরচনা glob_path_stat {
	ৱর্ণ		*gps_path;
	সংরচনা stat	*gps_stat;
};

স্থির পূর্ণাঙ্ক	 compare(ধ্রুৱ শূন্য *, ধ্রুৱ শূন্য *);
স্থির পূর্ণাঙ্ক	 compare_gps(ধ্রুৱ শূন্য *, ধ্রুৱ শূন্য *);
স্থির পূর্ণাঙ্ক	 g_Ctoc(ধ্রুৱ Char *, ৱর্ণ *, size_t);
স্থির পূর্ণাঙ্ক	 g_lstat(Char *, সংরচনা stat *, glob_t *);
স্থির DIR	*g_opendir(Char *, glob_t *);
স্থির Char	*g_strchr(ধ্রুৱ Char *, পূর্ণাঙ্ক);
স্থির পূর্ণাঙ্ক	 g_strncmp(ধ্রুৱ Char *, ধ্রুৱ ৱর্ণ *, size_t);
স্থির পূর্ণাঙ্ক	 g_stat(Char *, সংরচনা stat *, glob_t *);
স্থির পূর্ণাঙ্ক	 glob0(ধ্রুৱ Char *, glob_t *, সংরচনা glob_lim *);
স্থির পূর্ণাঙ্ক	 glob1(Char *, Char *, glob_t *, সংরচনা glob_lim *);
স্থির পূর্ণাঙ্ক	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, সংরচনা glob_lim *);
স্থির পূর্ণাঙ্ক	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, সংরচনা glob_lim *);
স্থির পূর্ণাঙ্ক	 globextend(ধ্রুৱ Char *, glob_t *, সংরচনা glob_lim *,
		    সংরচনা stat *);
স্থির ধ্রুৱ Char *
		 globtilde(ধ্রুৱ Char *, Char *, size_t, glob_t *);
স্থির পূর্ণাঙ্ক	 globexp1(ধ্রুৱ Char *, glob_t *, সংরচনা glob_lim *);
স্থির পূর্ণাঙ্ক	 globexp2(ধ্রুৱ Char *, ধ্রুৱ Char *, glob_t *,
		    সংরচনা glob_lim *);
স্থির পূর্ণাঙ্ক	 match(Char *, Char *, Char *);
#ifdef DEBUG
স্থির শূন্য	 qprintf(ধ্রুৱ ৱর্ণ *, Char *);
#endif

পূর্ণাঙ্ক
glob(ধ্রুৱ ৱর্ণ *pattern, পূর্ণাঙ্ক flags, পূর্ণাঙ্ক (*errfunc)(ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক),
    glob_t *pglob)
{
	ধ্রুৱ u_char *patnext;
	পূর্ণাঙ্ক c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	সংরচনা glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	যদি (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = রিক্ত;
		pglob->gl_statv = রিক্ত;
		যদি (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	যদি (strnlen(pattern, PATH_MAX) == PATH_MAX)
		ঘূৰাই(GLOB_NOMATCH);

	যদি (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		ঘূৰাই GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	যদি (flags & GLOB_NOESCAPE)
		যেতিয়ালৈ (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	অন্যথা {
		/* Protect the quoted characters. */
		যেতিয়ালৈ (bufnext < bufend && (c = *patnext++) != EOS)
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
		ঘূৰাই globexp1(patbuf, pglob, &limit);
	অন্যথা
		ঘূৰাই glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
স্থির পূর্ণাঙ্ক
globexp1(ধ্রুৱ Char *pattern, glob_t *pglob, সংরচনা glob_lim *limitp)
{
	ধ্রুৱ Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	যদি (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		ঘূৰাই glob0(pattern, pglob, limitp);

	যদি ((ptr = (ধ্রুৱ Char *) g_strchr(ptr, LBRACE)) != রিক্ত)
		ঘূৰাই globexp2(ptr, pattern, pglob, limitp);

	ঘূৰাই glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
স্থির পূর্ণাঙ্ক
globexp2(ধ্রুৱ Char *ptr, ধ্রুৱ Char *pattern, glob_t *pglob,
    সংরচনা glob_lim *limitp)
{
	পূর্ণাঙ্ক     i, rv;
	Char   *lm, *ls;
	ধ্রুৱ Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	বাবে (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	বাবে (i = 0, pe = ++ptr; *pe; pe++)
		যদি (*pe == LBRACKET) {
			/* Ignore everything between [] */
			বাবে (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
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
				ভঙ্গ;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	যদি (i != 0 || *pe == EOS)
		ঘূৰাই glob0(patbuf, pglob, limitp);

	বাবে (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		ৱিকল্প (*pm) {
		পক্ষ LBRACKET:
			/* Ignore everything between [] */
			বাবে (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			যদি (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			ভঙ্গ;

		পক্ষ LBRACE:
			i++;
			ভঙ্গ;

		পক্ষ RBRACE:
			যদি (i) {
				i--;
				ভঙ্গ;
			}
			/* FALLTHROUGH */
		পক্ষ COMMA:
			যদি (i && *pm == COMMA)
				ভঙ্গ;
			অন্যথা {
				/* Append the current string */
				বাবে (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				বাবে (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				যদি (rv && rv != GLOB_NOMATCH)
					ঘূৰাই rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			ভঙ্গ;

		স্ৱভাৱ:
			ভঙ্গ;
		}
	}
	ঘূৰাই 0;
}



/*
 * expand tilde from the passwd file.
 */
স্থির ধ্রুৱ Char *
globtilde(ধ্রুৱ Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	সংরচনা passwd *pwd;
	ৱর্ণ *h;
	ধ্রুৱ Char *p;
	Char *b, *eb;

	যদি (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		ঘূৰাই pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	বাবে (p = pattern + 1, h = (ৱর্ণ *) patbuf;
	    h < (ৱর্ণ *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#যদি 0
	যদি (h == (ৱর্ণ *)eb)
		ঘূৰাই what;
#endif

	যদি (((ৱর্ণ *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#যদি 0
		যদি (issetugid() != 0 || (h = getenv("HOME")) == রিক্ত) {
#endif
		যদি ((getuid() != geteuid()) || (h = getenv("HOME")) == রিক্ত) {
			যদি ((pwd = getpwuid(getuid())) == রিক্ত)
				ঘূৰাই pattern;
			অন্যথা
				h = pwd->pw_dir;
		}
	} অন্যথা {
		/*
		 * Expand a ~user
		 */
		যদি ((pwd = getpwnam((ৱর্ণ*) patbuf)) == রিক্ত)
			ঘূৰাই pattern;
		অন্যথা
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	বাবে (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	যেতিয়ালৈ (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	ঘূৰাই patbuf;
}

স্থির পূর্ণাঙ্ক
g_strncmp(ধ্রুৱ Char *s1, ধ্রুৱ ৱর্ণ *s2, size_t n)
{
	পূর্ণাঙ্ক rv = 0;

	যেতিয়ালৈ (n--) {
		rv = *(Char *)s1 - *(ধ্রুৱ unsigned ৱর্ণ *)s2++;
		যদি (rv)
			ভঙ্গ;
		যদি (*s1++ == '\0')
			ভঙ্গ;
	}
	ঘূৰাই rv;
}

স্থির পূর্ণাঙ্ক
g_charclass(ধ্রুৱ Char **patternp, Char **bufnextp)
{
	ধ্রুৱ Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	ধ্রুৱ Char *colon;
	সংরচনা cclass *cc;
	size_t len;

	যদি ((colon = g_strchr(pattern, ':')) == রিক্ত || colon[1] != ']')
		ঘূৰাই 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	বাবে (cc = cclasses; cc->name != রিক্ত; cc++) {
		যদি (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			ভঙ্গ;
	}
	যদি (cc->name == রিক্ত)
		ঘূৰাই -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	ঘূৰাই 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
স্থির পূর্ণাঙ্ক
glob0(ধ্রুৱ Char *pattern, glob_t *pglob, সংরচনা glob_lim *limitp)
{
	ধ্রুৱ Char *qpatnext;
	পূর্ণাঙ্ক c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	যেতিয়ালৈ ((c = *qpatnext++) != EOS) {
		ৱিকল্প (c) {
		পক্ষ LBRACKET:
			c = *qpatnext;
			যদি (c == NOT)
				++qpatnext;
			যদি (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == রিক্ত) {
				*bufnext++ = LBRACKET;
				যদি (c == NOT)
					--qpatnext;
				ভঙ্গ;
			}
			*bufnext++ = M_SET;
			যদি (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			কৰা {
				যদি (c == LBRACKET && *qpatnext == ':') {
					কৰা {
						err = g_charclass(&qpatnext,
						    &bufnext);
						যদি (err)
							ভঙ্গ;
						c = *qpatnext++;
					} যেতিয়ালৈ (c == LBRACKET && *qpatnext == ':');
					যদি (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						ঘূৰাই GLOB_NOMATCH;
					যদি (c == RBRACKET)
						ভঙ্গ;
				}
				*bufnext++ = CHAR(c);
				যদি (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} যেতিয়ালৈ ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			ভঙ্গ;
		পক্ষ QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			ভঙ্গ;
		পক্ষ STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			যদি (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			ভঙ্গ;
		স্ৱভাৱ:
			*bufnext++ = CHAR(c);
			ভঙ্গ;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	যদি ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		ঘূৰাই(err);

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
			ঘূৰাই(globextend(pattern, pglob, limitp, রিক্ত));
		অন্যথা
			ঘূৰাই(GLOB_NOMATCH);
	}
	যদি (!(pglob->gl_flags & GLOB_NOSORT)) {
		যদি ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			সংরচনা glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			যদি ((path_stat = calloc(n, পরিমাণ(*path_stat))) == রিক্ত)
				ঘূৰাই GLOB_NOSPACE;
			বাবে (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, পরিমাণ(*path_stat), compare_gps);
			বাবে (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			মুক্ত(path_stat);
		} অন্যথা {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, পরিমাণ(ৱর্ণ *),
			    compare);
		}
	}
	ঘূৰাই(0);
}

স্থির পূর্ণাঙ্ক
compare(ধ্রুৱ শূন্য *p, ধ্রুৱ শূন্য *q)
{
	ঘূৰাই(strcmp(*(ৱর্ণ **)p, *(ৱর্ণ **)q));
}

স্থির পূর্ণাঙ্ক
compare_gps(ধ্রুৱ শূন্য *_p, ধ্রুৱ শূন্য *_q)
{
	ধ্রুৱ সংরচনা glob_path_stat *p = (ধ্রুৱ সংরচনা glob_path_stat *)_p;
	ধ্রুৱ সংরচনা glob_path_stat *q = (ধ্রুৱ সংরচনা glob_path_stat *)_q;

	ঘূৰাই(strcmp(p->gps_path, q->gps_path));
}

স্থির পূর্ণাঙ্ক
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, সংরচনা glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	যদি (*pattern == EOS)
		ঘূৰাই(0);
	ঘূৰাই(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
স্থির পূর্ণাঙ্ক
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, সংরচনা glob_lim *limitp)
{
	সংরচনা stat sb;
	Char *p, *q;
	পূর্ণাঙ্ক anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	বাবে (anymeta = 0;;) {
		যদি (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			যদি ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				ঘূৰাই(GLOB_NOSPACE);
			}
			যদি (g_lstat(pathbuf, &sb, pglob))
				ঘূৰাই(0);

			যদি (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				যদি (pathend+1 > pathend_last)
					ঘূৰাই (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			ঘূৰাই(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		যেতিয়ালৈ (*p != EOS && *p != SEP) {
			যদি (ismeta(*p))
				anymeta = 1;
			যদি (q+1 > pathend_last)
				ঘূৰাই (1);
			*q++ = *p++;
		}

		যদি (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			যেতিয়ালৈ (*pattern == SEP) {
				যদি (pathend+1 > pathend_last)
					ঘূৰাই (1);
				*pathend++ = *pattern++;
			}
		} অন্যথা
			/* Need expansion, recurse. */
			ঘূৰাই(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

স্থির পূর্ণাঙ্ক
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    সংরচনা glob_lim *limitp)
{
	সংরচনা dirent *dp;
	DIR *dirp;
	পূর্ণাঙ্ক err;
	ৱর্ণ buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	সংরচনা dirent *(*readdirfunc)(শূন্য *);

	যদি (pathend > pathend_last)
		ঘূৰাই (1);
	*pathend = EOS;
	errno = 0;

	যদি ((dirp = g_opendir(pathbuf, pglob)) == রিক্ত) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		যদি (pglob->gl_errfunc) {
			যদি (g_Ctoc(pathbuf, buf, পরিমাণ(buf)))
				ঘূৰাই(GLOB_ABORTED);
			যদি (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				ঘূৰাই(GLOB_ABORTED);
		}
		ঘূৰাই(0);
	}

	err = 0;

	/* Search directory for matching names. */
	যদি (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	অন্যথা
		readdirfunc = (সংরচনা dirent *(*)(শূন্য *))readdir;
	যেতিয়ালৈ ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		যদি ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			ভঙ্গ;
		}

		/* Initial DOT must be matched literally. */
		যদি (dp->d_name[0] == DOT && *pattern != DOT)
			অনুৱর্ত;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		যেতিয়ালৈ (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		যদি (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			ভঙ্গ;
		}

		যদি (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			অনুৱর্ত;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		যদি (err)
			ভঙ্গ;
	}

	যদি (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	অন্যথা
		closedir(dirp);
	ঘূৰাই(err);
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
স্থির পূর্ণাঙ্ক
globextend(ধ্রুৱ Char *path, glob_t *pglob, সংরচনা glob_lim *limitp,
    সংরচনা stat *sb)
{
	ৱর্ণ **pathv;
	size_t i, newn, len;
	ৱর্ণ *copy = রিক্ত;
	ধ্রুৱ Char *p;
	সংরচনা stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	যদি (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / পরিমাণ(*pathv) <= newn ||
	    SIZE_MAX / পরিমাণ(*statv) <= newn) {
 nospace:
		বাবে (i = pglob->gl_offs; i < newn - 2; i++) {
			যদি (pglob->gl_pathv && pglob->gl_pathv[i])
				মুক্ত(pglob->gl_pathv[i]);
			যদি ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				মুক্ত(pglob->gl_statv[i]);
		}
		মুক্ত(pglob->gl_pathv);
		pglob->gl_pathv = রিক্ত;
		মুক্ত(pglob->gl_statv);
		pglob->gl_statv = রিক্ত;
		ঘূৰাই(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, পরিমাণ(*pathv));
	যদি (pathv == রিক্ত)
		গচ্ছ nospace;
	যদি (pglob->gl_pathv == রিক্ত && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		বাবে (i = pglob->gl_offs; i > 0; i--)
			*--pathv = রিক্ত;
	}
	pglob->gl_pathv = pathv;

	যদি ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, পরিমাণ(*statv));
		যদি (statv == রিক্ত)
			গচ্ছ nospace;
		যদি (pglob->gl_statv == রিক্ত && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			বাবে (i = pglob->gl_offs; i > 0; i--)
				*--statv = রিক্ত;
		}
		pglob->gl_statv = statv;
		যদি (sb == রিক্ত)
			statv[pglob->gl_offs + pglob->gl_pathc] = রিক্ত;
		অন্যথা {
			limitp->glim_malloc += পরিমাণ(**statv);
			যদি ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				ঘূৰাই(GLOB_NOSPACE);
			}
			যদি ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(পরিমাণ(**statv))) == রিক্ত)
				গচ্ছ copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    পরিমাণ(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = রিক্ত;
	}

	বাবে (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	যদি ((copy = malloc(len)) != রিক্ত) {
		যদি (g_Ctoc(path, copy, len)) {
			মুক্ত(copy);
			ঘূৰাই(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = রিক্ত;

	যদি ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * পরিমাণ(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		ঘূৰাই(GLOB_NOSPACE);
	}
 copy_error:
	ঘূৰাই(copy == রিক্ত ? GLOB_NOSPACE : 0);
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
স্থির পূর্ণাঙ্ক
match(Char *name, Char *pat, Char *patend)
{
	পূর্ণাঙ্ক ok, negate_range;
	Char c, k;
	Char *nextp = রিক্ত;
	Char *nextn = রিক্ত;

loop:
	যেতিয়ালৈ (pat < patend) {
		c = *pat++;
		ৱিকল্প (c & M_MASK) {
		পক্ষ M_ALL:
			যেতিয়ালৈ (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			যদি (pat == patend)
				ঘূৰাই(1);
			যদি (*name == EOS)
				ঘূৰাই(0);
			nextn = name + 1;
			nextp = pat - 1;
			ভঙ্গ;
		পক্ষ M_ONE:
			যদি (*name++ == EOS)
				গচ্ছ fail;
			ভঙ্গ;
		পক্ষ M_SET:
			ok = 0;
			যদি ((k = *name++) == EOS)
				গচ্ছ fail;
			যদি ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			যেতিয়ালৈ (((c = *pat++) & M_MASK) != M_END) {
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
				গচ্ছ fail;
			ভঙ্গ;
		স্ৱভাৱ:
			যদি (*name++ != c)
				গচ্ছ fail;
			ভঙ্গ;
		}
	}
	যদি (*name == EOS)
		ঘূৰাই(1);

fail:
	যদি (nextn) {
		pat = nextp;
		name = nextn;
		গচ্ছ loop;
	}
	ঘূৰাই(0);
}

/* Free allocated data belonging to a glob_t structure. */
শূন্য
globfree(glob_t *pglob)
{
	size_t i;
	ৱর্ণ **pp;

	যদি (pglob->gl_pathv != রিক্ত) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		বাবে (i = pglob->gl_pathc; i--; ++pp)
			মুক্ত(*pp);
		মুক্ত(pglob->gl_pathv);
		pglob->gl_pathv = রিক্ত;
	}
	যদি (pglob->gl_statv != রিক্ত) {
		বাবে (i = 0; i < pglob->gl_pathc; i++) {
			মুক্ত(pglob->gl_statv[i]);
		}
		মুক্ত(pglob->gl_statv);
		pglob->gl_statv = রিক্ত;
	}
}

স্থির DIR *
g_opendir(Char *str, glob_t *pglob)
{
	ৱর্ণ buf[PATH_MAX];

	যদি (!*str)
		strlcpy(buf, ".", পরিমাণ buf);
	অন্যথা {
		যদি (g_Ctoc(str, buf, পরিমাণ(buf)))
			ঘূৰাই(রিক্ত);
	}

	যদি (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ঘূৰাই((*pglob->gl_opendir)(buf));

	ঘূৰাই(opendir(buf));
}

স্থির পূর্ণাঙ্ক
g_lstat(Char *fn, সংরচনা stat *sb, glob_t *pglob)
{
	ৱর্ণ buf[PATH_MAX];

	যদি (g_Ctoc(fn, buf, পরিমাণ(buf)))
		ঘূৰাই(-1);
	যদি (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ঘূৰাই((*pglob->gl_lstat)(buf, sb));
	ঘূৰাই(lstat(buf, sb));
}

স্থির পূর্ণাঙ্ক
g_stat(Char *fn, সংরচনা stat *sb, glob_t *pglob)
{
	ৱর্ণ buf[PATH_MAX];

	যদি (g_Ctoc(fn, buf, পরিমাণ(buf)))
		ঘূৰাই(-1);
	যদি (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ঘূৰাই((*pglob->gl_stat)(buf, sb));
	ঘূৰাই(stat(buf, sb));
}

স্থির Char *
g_strchr(ধ্রুৱ Char *str, পূর্ণাঙ্ক ch)
{
	কৰা {
		যদি (*str == ch)
			ঘূৰাই ((Char *)str);
	} যেতিয়ালৈ (*str++);
	ঘূৰাই (রিক্ত);
}

স্থির পূর্ণাঙ্ক
g_Ctoc(ধ্রুৱ Char *str, ৱর্ণ *buf, size_t len)
{

	যেতিয়ালৈ (len--) {
		যদি ((*buf++ = *str++) == EOS)
			ঘূৰাই (0);
	}
	ঘূৰাই (1);
}

#ifdef DEBUG
স্থির শূন্য
qprintf(ধ্রুৱ ৱর্ণ *str, Char *s)
{
	Char *p;

	(শূন্য)printf("%s:\n", str);
	বাবে (p = s; *p; p++)
		(শূন্য)printf("%c", CHAR(*p));
	(শূন্য)printf("\n");
	বাবে (p = s; *p; p++)
		(শূন্য)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(শূন্য)printf("\n");
	বাবে (p = s; *p; p++)
		(শূন্য)printf("%c", ismeta(*p) ? '_' : ' ');
	(শূন্য)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
