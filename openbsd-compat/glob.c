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

#અન્તર્ભાવ "includes.h"
#અન્તર્ભાવ "glob.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <dirent.h>
#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#જો !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#અન્તર્ભાવ "charclass.h"

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

પ્રકારવ્યાખ્યા u_short Char;

#નહીંતર

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

પ્રકારવ્યાખ્યા અક્ષર Char;

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

સંરચના glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

સંરચના glob_path_stat {
	અક્ષર		*gps_path;
	સંરચના stat	*gps_stat;
};

સ્થિર પૂર્ણાંક	 compare(અચલ શૂન્ય *, અચલ શૂન્ય *);
સ્થિર પૂર્ણાંક	 compare_gps(અચલ શૂન્ય *, અચલ શૂન્ય *);
સ્થિર પૂર્ણાંક	 g_Ctoc(અચલ Char *, અક્ષર *, size_t);
સ્થિર પૂર્ણાંક	 g_lstat(Char *, સંરચના stat *, glob_t *);
સ્થિર DIR	*g_opendir(Char *, glob_t *);
સ્થિર Char	*g_strchr(અચલ Char *, પૂર્ણાંક);
સ્થિર પૂર્ણાંક	 g_strncmp(અચલ Char *, અચલ અક્ષર *, size_t);
સ્થિર પૂર્ણાંક	 g_stat(Char *, સંરચના stat *, glob_t *);
સ્થિર પૂર્ણાંક	 glob0(અચલ Char *, glob_t *, સંરચના glob_lim *);
સ્થિર પૂર્ણાંક	 glob1(Char *, Char *, glob_t *, સંરચના glob_lim *);
સ્થિર પૂર્ણાંક	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, સંરચના glob_lim *);
સ્થિર પૂર્ણાંક	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, સંરચના glob_lim *);
સ્થિર પૂર્ણાંક	 globextend(અચલ Char *, glob_t *, સંરચના glob_lim *,
		    સંરચના stat *);
સ્થિર અચલ Char *
		 globtilde(અચલ Char *, Char *, size_t, glob_t *);
સ્થિર પૂર્ણાંક	 globexp1(અચલ Char *, glob_t *, સંરચના glob_lim *);
સ્થિર પૂર્ણાંક	 globexp2(અચલ Char *, અચલ Char *, glob_t *,
		    સંરચના glob_lim *);
સ્થિર પૂર્ણાંક	 match(Char *, Char *, Char *);
#ifdef DEBUG
સ્થિર શૂન્ય	 qprintf(અચલ અક્ષર *, Char *);
#endif

પૂર્ણાંક
glob(અચલ અક્ષર *pattern, પૂર્ણાંક flags, પૂર્ણાંક (*errfunc)(અચલ અક્ષર *, પૂર્ણાંક),
    glob_t *pglob)
{
	અચલ u_char *patnext;
	પૂર્ણાંક c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	સંરચના glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	જો (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = ખાલી;
		pglob->gl_statv = ખાલી;
		જો (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	જો (strnlen(pattern, PATH_MAX) == PATH_MAX)
		પાછા(GLOB_NOMATCH);

	જો (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		પાછા GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	જો (flags & GLOB_NOESCAPE)
		જ્યારે (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	નહીંતર {
		/* Protect the quoted characters. */
		જ્યારે (bufnext < bufend && (c = *patnext++) != EOS)
			જો (c == QUOTE) {
				જો ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} નહીંતર
				*bufnext++ = c;
	}
	*bufnext = EOS;

	જો (flags & GLOB_BRACE)
		પાછા globexp1(patbuf, pglob, &limit);
	નહીંતર
		પાછા glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
સ્થિર પૂર્ણાંક
globexp1(અચલ Char *pattern, glob_t *pglob, સંરચના glob_lim *limitp)
{
	અચલ Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	જો (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		પાછા glob0(pattern, pglob, limitp);

	જો ((ptr = (અચલ Char *) g_strchr(ptr, LBRACE)) != ખાલી)
		પાછા globexp2(ptr, pattern, pglob, limitp);

	પાછા glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
સ્થિર પૂર્ણાંક
globexp2(અચલ Char *ptr, અચલ Char *pattern, glob_t *pglob,
    સંરચના glob_lim *limitp)
{
	પૂર્ણાંક     i, rv;
	Char   *lm, *ls;
	અચલ Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	માટે (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	માટે (i = 0, pe = ++ptr; *pe; pe++)
		જો (*pe == LBRACKET) {
			/* Ignore everything between [] */
			માટે (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			જો (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} નહીંતર જો (*pe == LBRACE)
			i++;
		નહીંતર જો (*pe == RBRACE) {
			જો (i == 0)
				તોડો;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	જો (i != 0 || *pe == EOS)
		પાછા glob0(patbuf, pglob, limitp);

	માટે (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		પસંદગી (*pm) {
		સ્થિતિ LBRACKET:
			/* Ignore everything between [] */
			માટે (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			જો (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			તોડો;

		સ્થિતિ LBRACE:
			i++;
			તોડો;

		સ્થિતિ RBRACE:
			જો (i) {
				i--;
				તોડો;
			}
			/* FALLTHROUGH */
		સ્થિતિ COMMA:
			જો (i && *pm == COMMA)
				તોડો;
			નહીંતર {
				/* Append the current string */
				માટે (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				માટે (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				જો (rv && rv != GLOB_NOMATCH)
					પાછા rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			તોડો;

		મૂળભૂત:
			તોડો;
		}
	}
	પાછા 0;
}



/*
 * expand tilde from the passwd file.
 */
સ્થિર અચલ Char *
globtilde(અચલ Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	સંરચના passwd *pwd;
	અક્ષર *h;
	અચલ Char *p;
	Char *b, *eb;

	જો (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		પાછા pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	માટે (p = pattern + 1, h = (અક્ષર *) patbuf;
	    h < (અક્ષર *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#જો 0
	જો (h == (અક્ષર *)eb)
		પાછા what;
#endif

	જો (((અક્ષર *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#જો 0
		જો (issetugid() != 0 || (h = getenv("HOME")) == ખાલી) {
#endif
		જો ((getuid() != geteuid()) || (h = getenv("HOME")) == ખાલી) {
			જો ((pwd = getpwuid(getuid())) == ખાલી)
				પાછા pattern;
			નહીંતર
				h = pwd->pw_dir;
		}
	} નહીંતર {
		/*
		 * Expand a ~user
		 */
		જો ((pwd = getpwnam((અક્ષર*) patbuf)) == ખાલી)
			પાછા pattern;
		નહીંતર
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	માટે (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	જ્યારે (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	પાછા patbuf;
}

સ્થિર પૂર્ણાંક
g_strncmp(અચલ Char *s1, અચલ અક્ષર *s2, size_t n)
{
	પૂર્ણાંક rv = 0;

	જ્યારે (n--) {
		rv = *(Char *)s1 - *(અચલ unsigned અક્ષર *)s2++;
		જો (rv)
			તોડો;
		જો (*s1++ == '\0')
			તોડો;
	}
	પાછા rv;
}

સ્થિર પૂર્ણાંક
g_charclass(અચલ Char **patternp, Char **bufnextp)
{
	અચલ Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	અચલ Char *colon;
	સંરચના cclass *cc;
	size_t len;

	જો ((colon = g_strchr(pattern, ':')) == ખાલી || colon[1] != ']')
		પાછા 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	માટે (cc = cclasses; cc->name != ખાલી; cc++) {
		જો (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			તોડો;
	}
	જો (cc->name == ખાલી)
		પાછા -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	પાછા 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
સ્થિર પૂર્ણાંક
glob0(અચલ Char *pattern, glob_t *pglob, સંરચના glob_lim *limitp)
{
	અચલ Char *qpatnext;
	પૂર્ણાંક c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	જ્યારે ((c = *qpatnext++) != EOS) {
		પસંદગી (c) {
		સ્થિતિ LBRACKET:
			c = *qpatnext;
			જો (c == NOT)
				++qpatnext;
			જો (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == ખાલી) {
				*bufnext++ = LBRACKET;
				જો (c == NOT)
					--qpatnext;
				તોડો;
			}
			*bufnext++ = M_SET;
			જો (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			કરો {
				જો (c == LBRACKET && *qpatnext == ':') {
					કરો {
						err = g_charclass(&qpatnext,
						    &bufnext);
						જો (err)
							તોડો;
						c = *qpatnext++;
					} જ્યારે (c == LBRACKET && *qpatnext == ':');
					જો (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						પાછા GLOB_NOMATCH;
					જો (c == RBRACKET)
						તોડો;
				}
				*bufnext++ = CHAR(c);
				જો (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} જ્યારે ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			તોડો;
		સ્થિતિ QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			તોડો;
		સ્થિતિ STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			જો (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			તોડો;
		મૂળભૂત:
			*bufnext++ = CHAR(c);
			તોડો;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	જો ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		પાછા(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	જો (pglob->gl_pathc == oldpathc) {
		જો ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			પાછા(globextend(pattern, pglob, limitp, ખાલી));
		નહીંતર
			પાછા(GLOB_NOMATCH);
	}
	જો (!(pglob->gl_flags & GLOB_NOSORT)) {
		જો ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			સંરચના glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			જો ((path_stat = calloc(n, કદ(*path_stat))) == ખાલી)
				પાછા GLOB_NOSPACE;
			માટે (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, કદ(*path_stat), compare_gps);
			માટે (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			મુક્ત(path_stat);
		} નહીંતર {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, કદ(અક્ષર *),
			    compare);
		}
	}
	પાછા(0);
}

સ્થિર પૂર્ણાંક
compare(અચલ શૂન્ય *p, અચલ શૂન્ય *q)
{
	પાછા(strcmp(*(અક્ષર **)p, *(અક્ષર **)q));
}

સ્થિર પૂર્ણાંક
compare_gps(અચલ શૂન્ય *_p, અચલ શૂન્ય *_q)
{
	અચલ સંરચના glob_path_stat *p = (અચલ સંરચના glob_path_stat *)_p;
	અચલ સંરચના glob_path_stat *q = (અચલ સંરચના glob_path_stat *)_q;

	પાછા(strcmp(p->gps_path, q->gps_path));
}

સ્થિર પૂર્ણાંક
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, સંરચના glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	જો (*pattern == EOS)
		પાછા(0);
	પાછા(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
સ્થિર પૂર્ણાંક
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, સંરચના glob_lim *limitp)
{
	સંરચના stat sb;
	Char *p, *q;
	પૂર્ણાંક anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	માટે (anymeta = 0;;) {
		જો (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			જો ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				પાછા(GLOB_NOSPACE);
			}
			જો (g_lstat(pathbuf, &sb, pglob))
				પાછા(0);

			જો (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				જો (pathend+1 > pathend_last)
					પાછા (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			પાછા(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		જ્યારે (*p != EOS && *p != SEP) {
			જો (ismeta(*p))
				anymeta = 1;
			જો (q+1 > pathend_last)
				પાછા (1);
			*q++ = *p++;
		}

		જો (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			જ્યારે (*pattern == SEP) {
				જો (pathend+1 > pathend_last)
					પાછા (1);
				*pathend++ = *pattern++;
			}
		} નહીંતર
			/* Need expansion, recurse. */
			પાછા(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

સ્થિર પૂર્ણાંક
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    સંરચના glob_lim *limitp)
{
	સંરચના dirent *dp;
	DIR *dirp;
	પૂર્ણાંક err;
	અક્ષર buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	સંરચના dirent *(*readdirfunc)(શૂન્ય *);

	જો (pathend > pathend_last)
		પાછા (1);
	*pathend = EOS;
	errno = 0;

	જો ((dirp = g_opendir(pathbuf, pglob)) == ખાલી) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		જો (pglob->gl_errfunc) {
			જો (g_Ctoc(pathbuf, buf, કદ(buf)))
				પાછા(GLOB_ABORTED);
			જો (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				પાછા(GLOB_ABORTED);
		}
		પાછા(0);
	}

	err = 0;

	/* Search directory for matching names. */
	જો (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	નહીંતર
		readdirfunc = (સંરચના dirent *(*)(શૂન્ય *))readdir;
	જ્યારે ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		જો ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			તોડો;
		}

		/* Initial DOT must be matched literally. */
		જો (dp->d_name[0] == DOT && *pattern != DOT)
			ચાલુ;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		જ્યારે (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		જો (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			તોડો;
		}

		જો (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			ચાલુ;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		જો (err)
			તોડો;
	}

	જો (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	નહીંતર
		closedir(dirp);
	પાછા(err);
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
સ્થિર પૂર્ણાંક
globextend(અચલ Char *path, glob_t *pglob, સંરચના glob_lim *limitp,
    સંરચના stat *sb)
{
	અક્ષર **pathv;
	size_t i, newn, len;
	અક્ષર *copy = ખાલી;
	અચલ Char *p;
	સંરચના stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	જો (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / કદ(*pathv) <= newn ||
	    SIZE_MAX / કદ(*statv) <= newn) {
 nospace:
		માટે (i = pglob->gl_offs; i < newn - 2; i++) {
			જો (pglob->gl_pathv && pglob->gl_pathv[i])
				મુક્ત(pglob->gl_pathv[i]);
			જો ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				મુક્ત(pglob->gl_statv[i]);
		}
		મુક્ત(pglob->gl_pathv);
		pglob->gl_pathv = ખાલી;
		મુક્ત(pglob->gl_statv);
		pglob->gl_statv = ખાલી;
		પાછા(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, કદ(*pathv));
	જો (pathv == ખાલી)
		જાઓ nospace;
	જો (pglob->gl_pathv == ખાલી && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		માટે (i = pglob->gl_offs; i > 0; i--)
			*--pathv = ખાલી;
	}
	pglob->gl_pathv = pathv;

	જો ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, કદ(*statv));
		જો (statv == ખાલી)
			જાઓ nospace;
		જો (pglob->gl_statv == ખાલી && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			માટે (i = pglob->gl_offs; i > 0; i--)
				*--statv = ખાલી;
		}
		pglob->gl_statv = statv;
		જો (sb == ખાલી)
			statv[pglob->gl_offs + pglob->gl_pathc] = ખાલી;
		નહીંતર {
			limitp->glim_malloc += કદ(**statv);
			જો ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				પાછા(GLOB_NOSPACE);
			}
			જો ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(કદ(**statv))) == ખાલી)
				જાઓ copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    કદ(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = ખાલી;
	}

	માટે (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	જો ((copy = malloc(len)) != ખાલી) {
		જો (g_Ctoc(path, copy, len)) {
			મુક્ત(copy);
			પાછા(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = ખાલી;

	જો ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * કદ(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		પાછા(GLOB_NOSPACE);
	}
 copy_error:
	પાછા(copy == ખાલી ? GLOB_NOSPACE : 0);
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
સ્થિર પૂર્ણાંક
match(Char *name, Char *pat, Char *patend)
{
	પૂર્ણાંક ok, negate_range;
	Char c, k;
	Char *nextp = ખાલી;
	Char *nextn = ખાલી;

loop:
	જ્યારે (pat < patend) {
		c = *pat++;
		પસંદગી (c & M_MASK) {
		સ્થિતિ M_ALL:
			જ્યારે (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			જો (pat == patend)
				પાછા(1);
			જો (*name == EOS)
				પાછા(0);
			nextn = name + 1;
			nextp = pat - 1;
			તોડો;
		સ્થિતિ M_ONE:
			જો (*name++ == EOS)
				જાઓ fail;
			તોડો;
		સ્થિતિ M_SET:
			ok = 0;
			જો ((k = *name++) == EOS)
				જાઓ fail;
			જો ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			જ્યારે (((c = *pat++) & M_MASK) != M_END) {
				જો ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					જો (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				જો ((*pat & M_MASK) == M_RNG) {
					જો (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} નહીંતર જો (c == k)
					ok = 1;
			}
			જો (ok == negate_range)
				જાઓ fail;
			તોડો;
		મૂળભૂત:
			જો (*name++ != c)
				જાઓ fail;
			તોડો;
		}
	}
	જો (*name == EOS)
		પાછા(1);

fail:
	જો (nextn) {
		pat = nextp;
		name = nextn;
		જાઓ loop;
	}
	પાછા(0);
}

/* Free allocated data belonging to a glob_t structure. */
શૂન્ય
globfree(glob_t *pglob)
{
	size_t i;
	અક્ષર **pp;

	જો (pglob->gl_pathv != ખાલી) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		માટે (i = pglob->gl_pathc; i--; ++pp)
			મુક્ત(*pp);
		મુક્ત(pglob->gl_pathv);
		pglob->gl_pathv = ખાલી;
	}
	જો (pglob->gl_statv != ખાલી) {
		માટે (i = 0; i < pglob->gl_pathc; i++) {
			મુક્ત(pglob->gl_statv[i]);
		}
		મુક્ત(pglob->gl_statv);
		pglob->gl_statv = ખાલી;
	}
}

સ્થિર DIR *
g_opendir(Char *str, glob_t *pglob)
{
	અક્ષર buf[PATH_MAX];

	જો (!*str)
		strlcpy(buf, ".", કદ buf);
	નહીંતર {
		જો (g_Ctoc(str, buf, કદ(buf)))
			પાછા(ખાલી);
	}

	જો (pglob->gl_flags & GLOB_ALTDIRFUNC)
		પાછા((*pglob->gl_opendir)(buf));

	પાછા(opendir(buf));
}

સ્થિર પૂર્ણાંક
g_lstat(Char *fn, સંરચના stat *sb, glob_t *pglob)
{
	અક્ષર buf[PATH_MAX];

	જો (g_Ctoc(fn, buf, કદ(buf)))
		પાછા(-1);
	જો (pglob->gl_flags & GLOB_ALTDIRFUNC)
		પાછા((*pglob->gl_lstat)(buf, sb));
	પાછા(lstat(buf, sb));
}

સ્થિર પૂર્ણાંક
g_stat(Char *fn, સંરચના stat *sb, glob_t *pglob)
{
	અક્ષર buf[PATH_MAX];

	જો (g_Ctoc(fn, buf, કદ(buf)))
		પાછા(-1);
	જો (pglob->gl_flags & GLOB_ALTDIRFUNC)
		પાછા((*pglob->gl_stat)(buf, sb));
	પાછા(stat(buf, sb));
}

સ્થિર Char *
g_strchr(અચલ Char *str, પૂર્ણાંક ch)
{
	કરો {
		જો (*str == ch)
			પાછા ((Char *)str);
	} જ્યારે (*str++);
	પાછા (ખાલી);
}

સ્થિર પૂર્ણાંક
g_Ctoc(અચલ Char *str, અક્ષર *buf, size_t len)
{

	જ્યારે (len--) {
		જો ((*buf++ = *str++) == EOS)
			પાછા (0);
	}
	પાછા (1);
}

#ifdef DEBUG
સ્થિર શૂન્ય
qprintf(અચલ અક્ષર *str, Char *s)
{
	Char *p;

	(શૂન્ય)printf("%s:\n", str);
	માટે (p = s; *p; p++)
		(શૂન્ય)printf("%c", CHAR(*p));
	(શૂન્ય)printf("\n");
	માટે (p = s; *p; p++)
		(શૂન્ય)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(શૂન્ય)printf("\n");
	માટે (p = s; *p; p++)
		(શૂન્ય)printf("%c", ismeta(*p) ? '_' : ' ');
	(શૂન્ય)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
