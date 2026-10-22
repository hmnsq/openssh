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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଅନ୍ତର୍ଭାଵ "glob.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <dirent.h>
#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଯଦି !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#ଅନ୍ତର୍ଭାଵ "charclass.h"

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

ପ୍ରକାରବ୍ୟାଖ୍ୟା u_short Char;

#ଅନ୍ୟଥା

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

ପ୍ରକାରବ୍ୟାଖ୍ୟା ଅକ୍ଷର Char;

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

ସଂରଚନା glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

ସଂରଚନା glob_path_stat {
	ଅକ୍ଷର		*gps_path;
	ସଂରଚନା stat	*gps_stat;
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 compare(ଅଚଳ ଶୂନ୍ୟ *, ଅଚଳ ଶୂନ୍ୟ *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 compare_gps(ଅଚଳ ଶୂନ୍ୟ *, ଅଚଳ ଶୂନ୍ୟ *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 g_Ctoc(ଅଚଳ Char *, ଅକ୍ଷର *, size_t);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 g_lstat(Char *, ସଂରଚନା stat *, glob_t *);
ସ୍ଥିର DIR	*g_opendir(Char *, glob_t *);
ସ୍ଥିର Char	*g_strchr(ଅଚଳ Char *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 g_strncmp(ଅଚଳ Char *, ଅଚଳ ଅକ୍ଷର *, size_t);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 g_stat(Char *, ସଂରଚନା stat *, glob_t *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 glob0(ଅଚଳ Char *, glob_t *, ସଂରଚନା glob_lim *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 glob1(Char *, Char *, glob_t *, ସଂରଚନା glob_lim *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, ସଂରଚନା glob_lim *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, ସଂରଚନା glob_lim *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 globextend(ଅଚଳ Char *, glob_t *, ସଂରଚନା glob_lim *,
		    ସଂରଚନା stat *);
ସ୍ଥିର ଅଚଳ Char *
		 globtilde(ଅଚଳ Char *, Char *, size_t, glob_t *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 globexp1(ଅଚଳ Char *, glob_t *, ସଂରଚନା glob_lim *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 globexp2(ଅଚଳ Char *, ଅଚଳ Char *, glob_t *,
		    ସଂରଚନା glob_lim *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 match(Char *, Char *, Char *);
#ifdef DEBUG
ସ୍ଥିର ଶୂନ୍ୟ	 qprintf(ଅଚଳ ଅକ୍ଷର *, Char *);
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
glob(ଅଚଳ ଅକ୍ଷର *pattern, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags, ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*errfunc)(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା),
    glob_t *pglob)
{
	ଅଚଳ u_char *patnext;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	ସଂରଚନା glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	ଯଦି (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = ଖାଲି;
		pglob->gl_statv = ଖାଲି;
		ଯଦି (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	ଯଦି (strnlen(pattern, PATH_MAX) == PATH_MAX)
		ଫେରନ୍ତୁ(GLOB_NOMATCH);

	ଯଦି (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		ଫେରନ୍ତୁ GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	ଯଦି (flags & GLOB_NOESCAPE)
		ଯେତେବେଳେ (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	ଅନ୍ୟଥା {
		/* Protect the quoted characters. */
		ଯେତେବେଳେ (bufnext < bufend && (c = *patnext++) != EOS)
			ଯଦି (c == QUOTE) {
				ଯଦି ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} ଅନ୍ୟଥା
				*bufnext++ = c;
	}
	*bufnext = EOS;

	ଯଦି (flags & GLOB_BRACE)
		ଫେରନ୍ତୁ globexp1(patbuf, pglob, &limit);
	ଅନ୍ୟଥା
		ଫେରନ୍ତୁ glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
globexp1(ଅଚଳ Char *pattern, glob_t *pglob, ସଂରଚନା glob_lim *limitp)
{
	ଅଚଳ Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	ଯଦି (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		ଫେରନ୍ତୁ glob0(pattern, pglob, limitp);

	ଯଦି ((ptr = (ଅଚଳ Char *) g_strchr(ptr, LBRACE)) != ଖାଲି)
		ଫେରନ୍ତୁ globexp2(ptr, pattern, pglob, limitp);

	ଫେରନ୍ତୁ glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
globexp2(ଅଚଳ Char *ptr, ଅଚଳ Char *pattern, glob_t *pglob,
    ସଂରଚନା glob_lim *limitp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା     i, rv;
	Char   *lm, *ls;
	ଅଚଳ Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	ପାଇଁ (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	ପାଇଁ (i = 0, pe = ++ptr; *pe; pe++)
		ଯଦି (*pe == LBRACKET) {
			/* Ignore everything between [] */
			ପାଇଁ (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			ଯଦି (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} ଅନ୍ୟଥା ଯଦି (*pe == LBRACE)
			i++;
		ଅନ୍ୟଥା ଯଦି (*pe == RBRACE) {
			ଯଦି (i == 0)
				ଭାଙ୍ଗ;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	ଯଦି (i != 0 || *pe == EOS)
		ଫେରନ୍ତୁ glob0(patbuf, pglob, limitp);

	ପାଇଁ (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		ବାଛ (*pm) {
		ସ୍ଥିତି LBRACKET:
			/* Ignore everything between [] */
			ପାଇଁ (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			ଯଦି (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			ଭାଙ୍ଗ;

		ସ୍ଥିତି LBRACE:
			i++;
			ଭାଙ୍ଗ;

		ସ୍ଥିତି RBRACE:
			ଯଦି (i) {
				i--;
				ଭାଙ୍ଗ;
			}
			/* FALLTHROUGH */
		ସ୍ଥିତି COMMA:
			ଯଦି (i && *pm == COMMA)
				ଭାଙ୍ଗ;
			ଅନ୍ୟଥା {
				/* Append the current string */
				ପାଇଁ (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				ପାଇଁ (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				ଯଦି (rv && rv != GLOB_NOMATCH)
					ଫେରନ୍ତୁ rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			ଭାଙ୍ଗ;

		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଭାଙ୍ଗ;
		}
	}
	ଫେରନ୍ତୁ 0;
}



/*
 * expand tilde from the passwd file.
 */
ସ୍ଥିର ଅଚଳ Char *
globtilde(ଅଚଳ Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	ସଂରଚନା passwd *pwd;
	ଅକ୍ଷର *h;
	ଅଚଳ Char *p;
	Char *b, *eb;

	ଯଦି (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		ଫେରନ୍ତୁ pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	ପାଇଁ (p = pattern + 1, h = (ଅକ୍ଷର *) patbuf;
	    h < (ଅକ୍ଷର *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#ଯଦି 0
	ଯଦି (h == (ଅକ୍ଷର *)eb)
		ଫେରନ୍ତୁ what;
#endif

	ଯଦି (((ଅକ୍ଷର *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#ଯଦି 0
		ଯଦି (issetugid() != 0 || (h = getenv("HOME")) == ଖାଲି) {
#endif
		ଯଦି ((getuid() != geteuid()) || (h = getenv("HOME")) == ଖାଲି) {
			ଯଦି ((pwd = getpwuid(getuid())) == ଖାଲି)
				ଫେରନ୍ତୁ pattern;
			ଅନ୍ୟଥା
				h = pwd->pw_dir;
		}
	} ଅନ୍ୟଥା {
		/*
		 * Expand a ~user
		 */
		ଯଦି ((pwd = getpwnam((ଅକ୍ଷର*) patbuf)) == ଖାଲି)
			ଫେରନ୍ତୁ pattern;
		ଅନ୍ୟଥା
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	ପାଇଁ (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	ଯେତେବେଳେ (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	ଫେରନ୍ତୁ patbuf;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
g_strncmp(ଅଚଳ Char *s1, ଅଚଳ ଅକ୍ଷର *s2, size_t n)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rv = 0;

	ଯେତେବେଳେ (n--) {
		rv = *(Char *)s1 - *(ଅଚଳ unsigned ଅକ୍ଷର *)s2++;
		ଯଦି (rv)
			ଭାଙ୍ଗ;
		ଯଦି (*s1++ == '\0')
			ଭାଙ୍ଗ;
	}
	ଫେରନ୍ତୁ rv;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
g_charclass(ଅଚଳ Char **patternp, Char **bufnextp)
{
	ଅଚଳ Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	ଅଚଳ Char *colon;
	ସଂରଚନା cclass *cc;
	size_t len;

	ଯଦି ((colon = g_strchr(pattern, ':')) == ଖାଲି || colon[1] != ']')
		ଫେରନ୍ତୁ 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	ପାଇଁ (cc = cclasses; cc->name != ଖାଲି; cc++) {
		ଯଦି (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			ଭାଙ୍ଗ;
	}
	ଯଦି (cc->name == ଖାଲି)
		ଫେରନ୍ତୁ -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	ଫେରନ୍ତୁ 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
glob0(ଅଚଳ Char *pattern, glob_t *pglob, ସଂରଚନା glob_lim *limitp)
{
	ଅଚଳ Char *qpatnext;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	ଯେତେବେଳେ ((c = *qpatnext++) != EOS) {
		ବାଛ (c) {
		ସ୍ଥିତି LBRACKET:
			c = *qpatnext;
			ଯଦି (c == NOT)
				++qpatnext;
			ଯଦି (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == ଖାଲି) {
				*bufnext++ = LBRACKET;
				ଯଦି (c == NOT)
					--qpatnext;
				ଭାଙ୍ଗ;
			}
			*bufnext++ = M_SET;
			ଯଦି (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			କର {
				ଯଦି (c == LBRACKET && *qpatnext == ':') {
					କର {
						err = g_charclass(&qpatnext,
						    &bufnext);
						ଯଦି (err)
							ଭାଙ୍ଗ;
						c = *qpatnext++;
					} ଯେତେବେଳେ (c == LBRACKET && *qpatnext == ':');
					ଯଦି (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						ଫେରନ୍ତୁ GLOB_NOMATCH;
					ଯଦି (c == RBRACKET)
						ଭାଙ୍ଗ;
				}
				*bufnext++ = CHAR(c);
				ଯଦି (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} ଯେତେବେଳେ ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			ଯଦି (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			*bufnext++ = CHAR(c);
			ଭାଙ୍ଗ;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	ଯଦି ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		ଫେରନ୍ତୁ(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	ଯଦି (pglob->gl_pathc == oldpathc) {
		ଯଦି ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			ଫେରନ୍ତୁ(globextend(pattern, pglob, limitp, ଖାଲି));
		ଅନ୍ୟଥା
			ଫେରନ୍ତୁ(GLOB_NOMATCH);
	}
	ଯଦି (!(pglob->gl_flags & GLOB_NOSORT)) {
		ଯଦି ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			ସଂରଚନା glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			ଯଦି ((path_stat = calloc(n, ଆକାର(*path_stat))) == ଖାଲି)
				ଫେରନ୍ତୁ GLOB_NOSPACE;
			ପାଇଁ (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, ଆକାର(*path_stat), compare_gps);
			ପାଇଁ (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			ମୁକ୍ତ(path_stat);
		} ଅନ୍ୟଥା {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, ଆକାର(ଅକ୍ଷର *),
			    compare);
		}
	}
	ଫେରନ୍ତୁ(0);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
compare(ଅଚଳ ଶୂନ୍ୟ *p, ଅଚଳ ଶୂନ୍ୟ *q)
{
	ଫେରନ୍ତୁ(strcmp(*(ଅକ୍ଷର **)p, *(ଅକ୍ଷର **)q));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
compare_gps(ଅଚଳ ଶୂନ୍ୟ *_p, ଅଚଳ ଶୂନ୍ୟ *_q)
{
	ଅଚଳ ସଂରଚନା glob_path_stat *p = (ଅଚଳ ସଂରଚନା glob_path_stat *)_p;
	ଅଚଳ ସଂରଚନା glob_path_stat *q = (ଅଚଳ ସଂରଚନା glob_path_stat *)_q;

	ଫେରନ୍ତୁ(strcmp(p->gps_path, q->gps_path));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, ସଂରଚନା glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	ଯଦି (*pattern == EOS)
		ଫେରନ୍ତୁ(0);
	ଫେରନ୍ତୁ(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, ସଂରଚନା glob_lim *limitp)
{
	ସଂରଚନା stat sb;
	Char *p, *q;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	ପାଇଁ (anymeta = 0;;) {
		ଯଦି (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			ଯଦି ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				ଫେରନ୍ତୁ(GLOB_NOSPACE);
			}
			ଯଦି (g_lstat(pathbuf, &sb, pglob))
				ଫେରନ୍ତୁ(0);

			ଯଦି (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				ଯଦି (pathend+1 > pathend_last)
					ଫେରନ୍ତୁ (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			ଫେରନ୍ତୁ(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		ଯେତେବେଳେ (*p != EOS && *p != SEP) {
			ଯଦି (ismeta(*p))
				anymeta = 1;
			ଯଦି (q+1 > pathend_last)
				ଫେରନ୍ତୁ (1);
			*q++ = *p++;
		}

		ଯଦି (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			ଯେତେବେଳେ (*pattern == SEP) {
				ଯଦି (pathend+1 > pathend_last)
					ଫେରନ୍ତୁ (1);
				*pathend++ = *pattern++;
			}
		} ଅନ୍ୟଥା
			/* Need expansion, recurse. */
			ଫେରନ୍ତୁ(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    ସଂରଚନା glob_lim *limitp)
{
	ସଂରଚନା dirent *dp;
	DIR *dirp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା err;
	ଅକ୍ଷର buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	ସଂରଚନା dirent *(*readdirfunc)(ଶୂନ୍ୟ *);

	ଯଦି (pathend > pathend_last)
		ଫେରନ୍ତୁ (1);
	*pathend = EOS;
	errno = 0;

	ଯଦି ((dirp = g_opendir(pathbuf, pglob)) == ଖାଲି) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		ଯଦି (pglob->gl_errfunc) {
			ଯଦି (g_Ctoc(pathbuf, buf, ଆକାର(buf)))
				ଫେରନ୍ତୁ(GLOB_ABORTED);
			ଯଦି (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				ଫେରନ୍ତୁ(GLOB_ABORTED);
		}
		ଫେରନ୍ତୁ(0);
	}

	err = 0;

	/* Search directory for matching names. */
	ଯଦି (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	ଅନ୍ୟଥା
		readdirfunc = (ସଂରଚନା dirent *(*)(ଶୂନ୍ୟ *))readdir;
	ଯେତେବେଳେ ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		ଯଦି ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			ଭାଙ୍ଗ;
		}

		/* Initial DOT must be matched literally. */
		ଯଦି (dp->d_name[0] == DOT && *pattern != DOT)
			ଜାରି;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		ଯେତେବେଳେ (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		ଯଦି (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			ଭାଙ୍ଗ;
		}

		ଯଦି (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			ଜାରି;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		ଯଦି (err)
			ଭାଙ୍ଗ;
	}

	ଯଦି (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	ଅନ୍ୟଥା
		closedir(dirp);
	ଫେରନ୍ତୁ(err);
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
globextend(ଅଚଳ Char *path, glob_t *pglob, ସଂରଚନା glob_lim *limitp,
    ସଂରଚନା stat *sb)
{
	ଅକ୍ଷର **pathv;
	size_t i, newn, len;
	ଅକ୍ଷର *copy = ଖାଲି;
	ଅଚଳ Char *p;
	ସଂରଚନା stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	ଯଦି (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / ଆକାର(*pathv) <= newn ||
	    SIZE_MAX / ଆକାର(*statv) <= newn) {
 nospace:
		ପାଇଁ (i = pglob->gl_offs; i < newn - 2; i++) {
			ଯଦି (pglob->gl_pathv && pglob->gl_pathv[i])
				ମୁକ୍ତ(pglob->gl_pathv[i]);
			ଯଦି ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				ମୁକ୍ତ(pglob->gl_statv[i]);
		}
		ମୁକ୍ତ(pglob->gl_pathv);
		pglob->gl_pathv = ଖାଲି;
		ମୁକ୍ତ(pglob->gl_statv);
		pglob->gl_statv = ଖାଲି;
		ଫେରନ୍ତୁ(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, ଆକାର(*pathv));
	ଯଦି (pathv == ଖାଲି)
		ଯାଅ nospace;
	ଯଦି (pglob->gl_pathv == ଖାଲି && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		ପାଇଁ (i = pglob->gl_offs; i > 0; i--)
			*--pathv = ଖାଲି;
	}
	pglob->gl_pathv = pathv;

	ଯଦି ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, ଆକାର(*statv));
		ଯଦି (statv == ଖାଲି)
			ଯାଅ nospace;
		ଯଦି (pglob->gl_statv == ଖାଲି && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			ପାଇଁ (i = pglob->gl_offs; i > 0; i--)
				*--statv = ଖାଲି;
		}
		pglob->gl_statv = statv;
		ଯଦି (sb == ଖାଲି)
			statv[pglob->gl_offs + pglob->gl_pathc] = ଖାଲି;
		ଅନ୍ୟଥା {
			limitp->glim_malloc += ଆକାର(**statv);
			ଯଦି ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				ଫେରନ୍ତୁ(GLOB_NOSPACE);
			}
			ଯଦି ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(ଆକାର(**statv))) == ଖାଲି)
				ଯାଅ copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    ଆକାର(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = ଖାଲି;
	}

	ପାଇଁ (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	ଯଦି ((copy = malloc(len)) != ଖାଲି) {
		ଯଦି (g_Ctoc(path, copy, len)) {
			ମୁକ୍ତ(copy);
			ଫେରନ୍ତୁ(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = ଖାଲି;

	ଯଦି ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * ଆକାର(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		ଫେରନ୍ତୁ(GLOB_NOSPACE);
	}
 copy_error:
	ଫେରନ୍ତୁ(copy == ଖାଲି ? GLOB_NOSPACE : 0);
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match(Char *name, Char *pat, Char *patend)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ok, negate_range;
	Char c, k;
	Char *nextp = ଖାଲି;
	Char *nextn = ଖାଲି;

loop:
	ଯେତେବେଳେ (pat < patend) {
		c = *pat++;
		ବାଛ (c & M_MASK) {
		ସ୍ଥିତି M_ALL:
			ଯେତେବେଳେ (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			ଯଦି (pat == patend)
				ଫେରନ୍ତୁ(1);
			ଯଦି (*name == EOS)
				ଫେରନ୍ତୁ(0);
			nextn = name + 1;
			nextp = pat - 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି M_ONE:
			ଯଦି (*name++ == EOS)
				ଯାଅ fail;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି M_SET:
			ok = 0;
			ଯଦି ((k = *name++) == EOS)
				ଯାଅ fail;
			ଯଦି ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			ଯେତେବେଳେ (((c = *pat++) & M_MASK) != M_END) {
				ଯଦି ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					ଯଦି (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				ଯଦି ((*pat & M_MASK) == M_RNG) {
					ଯଦି (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} ଅନ୍ୟଥା ଯଦି (c == k)
					ok = 1;
			}
			ଯଦି (ok == negate_range)
				ଯାଅ fail;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଯଦି (*name++ != c)
				ଯାଅ fail;
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (*name == EOS)
		ଫେରନ୍ତୁ(1);

fail:
	ଯଦି (nextn) {
		pat = nextp;
		name = nextn;
		ଯାଅ loop;
	}
	ଫେରନ୍ତୁ(0);
}

/* Free allocated data belonging to a glob_t structure. */
ଶୂନ୍ୟ
globfree(glob_t *pglob)
{
	size_t i;
	ଅକ୍ଷର **pp;

	ଯଦି (pglob->gl_pathv != ଖାଲି) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		ପାଇଁ (i = pglob->gl_pathc; i--; ++pp)
			ମୁକ୍ତ(*pp);
		ମୁକ୍ତ(pglob->gl_pathv);
		pglob->gl_pathv = ଖାଲି;
	}
	ଯଦି (pglob->gl_statv != ଖାଲି) {
		ପାଇଁ (i = 0; i < pglob->gl_pathc; i++) {
			ମୁକ୍ତ(pglob->gl_statv[i]);
		}
		ମୁକ୍ତ(pglob->gl_statv);
		pglob->gl_statv = ଖାଲି;
	}
}

ସ୍ଥିର DIR *
g_opendir(Char *str, glob_t *pglob)
{
	ଅକ୍ଷର buf[PATH_MAX];

	ଯଦି (!*str)
		strlcpy(buf, ".", ଆକାର buf);
	ଅନ୍ୟଥା {
		ଯଦି (g_Ctoc(str, buf, ଆକାର(buf)))
			ଫେରନ୍ତୁ(ଖାଲି);
	}

	ଯଦି (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ଫେରନ୍ତୁ((*pglob->gl_opendir)(buf));

	ଫେରନ୍ତୁ(opendir(buf));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
g_lstat(Char *fn, ସଂରଚନା stat *sb, glob_t *pglob)
{
	ଅକ୍ଷର buf[PATH_MAX];

	ଯଦି (g_Ctoc(fn, buf, ଆକାର(buf)))
		ଫେରନ୍ତୁ(-1);
	ଯଦି (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ଫେରନ୍ତୁ((*pglob->gl_lstat)(buf, sb));
	ଫେରନ୍ତୁ(lstat(buf, sb));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
g_stat(Char *fn, ସଂରଚନା stat *sb, glob_t *pglob)
{
	ଅକ୍ଷର buf[PATH_MAX];

	ଯଦି (g_Ctoc(fn, buf, ଆକାର(buf)))
		ଫେରନ୍ତୁ(-1);
	ଯଦି (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ଫେରନ୍ତୁ((*pglob->gl_stat)(buf, sb));
	ଫେରନ୍ତୁ(stat(buf, sb));
}

ସ୍ଥିର Char *
g_strchr(ଅଚଳ Char *str, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch)
{
	କର {
		ଯଦି (*str == ch)
			ଫେରନ୍ତୁ ((Char *)str);
	} ଯେତେବେଳେ (*str++);
	ଫେରନ୍ତୁ (ଖାଲି);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
g_Ctoc(ଅଚଳ Char *str, ଅକ୍ଷର *buf, size_t len)
{

	ଯେତେବେଳେ (len--) {
		ଯଦି ((*buf++ = *str++) == EOS)
			ଫେରନ୍ତୁ (0);
	}
	ଫେରନ୍ତୁ (1);
}

#ifdef DEBUG
ସ୍ଥିର ଶୂନ୍ୟ
qprintf(ଅଚଳ ଅକ୍ଷର *str, Char *s)
{
	Char *p;

	(ଶୂନ୍ୟ)printf("%s:\n", str);
	ପାଇଁ (p = s; *p; p++)
		(ଶୂନ୍ୟ)printf("%c", CHAR(*p));
	(ଶୂନ୍ୟ)printf("\n");
	ପାଇଁ (p = s; *p; p++)
		(ଶୂନ୍ୟ)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(ଶୂନ୍ୟ)printf("\n");
	ପାଇଁ (p = s; *p; p++)
		(ଶୂନ୍ୟ)printf("%c", ismeta(*p) ? '_' : ' ');
	(ଶୂନ୍ୟ)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
