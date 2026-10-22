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

#అన్తర్భావ "includes.h"
#అన్తర్భావ "glob.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <dirent.h>
#అన్తర్భావ <ctype.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#ఒకవేళ !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#అన్తర్భావ "charclass.h"

#నిర్వచితమైతే TILDE
# undef TILDE
#అయితే_ముగింపు

#నిర్వచించు	DOLLAR		'$'
#నిర్వచించు	DOT		'.'
#నిర్వచించు	EOS		'\0'
#నిర్వచించు	LBRACKET	'['
#నిర్వచించు	NOT		'!'
#నిర్వచించు	QUESTION	'?'
#నిర్వచించు	QUOTE		'\\'
#నిర్వచించు	RANGE		'-'
#నిర్వచించు	RBRACKET	']'
#నిర్వచించు	SEP		'/'
#నిర్వచించు	నక్షత్రం		'*'
#నిర్వచించు	TILDE		'~'
#నిర్వచించు	UNDERSCORE	'_'
#నిర్వచించు	LBRACE		'{'
#నిర్వచించు	RBRACE		'}'
#నిర్వచించు	SLASH		'/'
#నిర్వచించు	COMMA		','

#నిర్వచితం_కాకపోతే DEBUG

#నిర్వచించు	M_QUOTE		0x8000
#నిర్వచించు	M_PROTECT	0x4000
#నిర్వచించు	M_ముసుగు		0xffff
#నిర్వచించు	M_ASCII		0x00ff

రకనిర్వచనం u_short Char;

#లేకపోతే

#నిర్వచించు	M_QUOTE		0x80
#నిర్వచించు	M_PROTECT	0x40
#నిర్వచించు	M_ముసుగు		0xff
#నిర్వచించు	M_ASCII		0x7f

రకనిర్వచనం అక్షరం Char;

#అయితే_ముగింపు


#నిర్వచించు	CHAR(c)		((Char)((c)&M_ASCII))
#నిర్వచించు	META(c)		((Char)((c)|M_QUOTE))
#నిర్వచించు	M_ALL		META('*')
#నిర్వచించు	M_చివర		META(']')
#నిర్వచించు	M_NOT		META('!')
#నిర్వచించు	M_ONE		META('?')
#నిర్వచించు	M_RNG		META('-')
#నిర్వచించు	M_సమితి		META('[')
#నిర్వచించు	M_CLASS		META(':')
#నిర్వచించు	ismeta(c)	(((c)&M_QUOTE) != 0)

#నిర్వచించు	GLOB_హద్దు_MALLOC	65536
#నిర్వచించు	GLOB_హద్దు_STAT		2048
#నిర్వచించు	GLOB_హద్దు_READDIR	16384

నిర్మాణం glob_lim {
	కొలత_t	glim_malloc;
	కొలత_t	glim_stat;
	కొలత_t	glim_readdir;
};

నిర్మాణం glob_మార్గం_stat {
	అక్షరం		*gps_మార్గం;
	నిర్మాణం stat	*gps_stat;
};

స్థిర పూర్ణాంకం	 compare(స్థిరరాశి శూన్య *, స్థిరరాశి శూన్య *);
స్థిర పూర్ణాంకం	 compare_gps(స్థిరరాశి శూన్య *, స్థిరరాశి శూన్య *);
స్థిర పూర్ణాంకం	 g_Ctoc(స్థిరరాశి Char *, అక్షరం *, కొలత_t);
స్థిర పూర్ణాంకం	 g_lstat(Char *, నిర్మాణం stat *, glob_t *);
స్థిర DIR	*g_opendir(Char *, glob_t *);
స్థిర Char	*g_strchr(స్థిరరాశి Char *, పూర్ణాంకం);
స్థిర పూర్ణాంకం	 g_strncmp(స్థిరరాశి Char *, స్థిరరాశి అక్షరం *, కొలత_t);
స్థిర పూర్ణాంకం	 g_stat(Char *, నిర్మాణం stat *, glob_t *);
స్థిర పూర్ణాంకం	 glob0(స్థిరరాశి Char *, glob_t *, నిర్మాణం glob_lim *);
స్థిర పూర్ణాంకం	 glob1(Char *, Char *, glob_t *, నిర్మాణం glob_lim *);
స్థిర పూర్ణాంకం	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, నిర్మాణం glob_lim *);
స్థిర పూర్ణాంకం	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, నిర్మాణం glob_lim *);
స్థిర పూర్ణాంకం	 globextend(స్థిరరాశి Char *, glob_t *, నిర్మాణం glob_lim *,
		    నిర్మాణం stat *);
స్థిర స్థిరరాశి Char *
		 globtilde(స్థిరరాశి Char *, Char *, కొలత_t, glob_t *);
స్థిర పూర్ణాంకం	 globexp1(స్థిరరాశి Char *, glob_t *, నిర్మాణం glob_lim *);
స్థిర పూర్ణాంకం	 globexp2(స్థిరరాశి Char *, స్థిరరాశి Char *, glob_t *,
		    నిర్మాణం glob_lim *);
స్థిర పూర్ణాంకం	 సరిపోలిక(Char *, Char *, Char *);
#నిర్వచితమైతే DEBUG
స్థిర శూన్య	 qprintf(స్థిరరాశి అక్షరం *, Char *);
#అయితే_ముగింపు

పూర్ణాంకం
glob(స్థిరరాశి అక్షరం *నమూనా, పూర్ణాంకం flags, పూర్ణాంకం (*errfunc)(స్థిరరాశి అక్షరం *, పూర్ణాంకం),
    glob_t *pglob)
{
	స్థిరరాశి u_char *patnext;
	పూర్ణాంకం c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	నిర్మాణం glob_lim హద్దు = { 0, 0, 0 };

	patnext = (u_char *) నమూనా;
	ఒకవేళ (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = ఖాళీ;
		pglob->gl_statv = ఖాళీ;
		ఒకవేళ (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	ఒకవేళ (strnlen(నమూనా, PATH_MAX) == PATH_MAX)
		తిరిగి(GLOB_NOMATCH);

	ఒకవేళ (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		తిరిగి GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	ఒకవేళ (flags & GLOB_NOESCAPE)
		అయితే (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	లేకపోతే {
		/* Protect the quoted characters. */
		అయితే (bufnext < bufend && (c = *patnext++) != EOS)
			ఒకవేళ (c == QUOTE) {
				ఒకవేళ ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} లేకపోతే
				*bufnext++ = c;
	}
	*bufnext = EOS;

	ఒకవేళ (flags & GLOB_BRACE)
		తిరిగి globexp1(patbuf, pglob, &హద్దు);
	లేకపోతే
		తిరిగి glob0(patbuf, pglob, &హద్దు);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
స్థిర పూర్ణాంకం
globexp1(స్థిరరాశి Char *నమూనా, glob_t *pglob, నిర్మాణం glob_lim *limitp)
{
	స్థిరరాశి Char* ptr = నమూనా;

	/* Protect a single {}, for find(1), like csh */
	ఒకవేళ (నమూనా[0] == LBRACE && నమూనా[1] == RBRACE && నమూనా[2] == EOS)
		తిరిగి glob0(నమూనా, pglob, limitp);

	ఒకవేళ ((ptr = (స్థిరరాశి Char *) g_strchr(ptr, LBRACE)) != ఖాళీ)
		తిరిగి globexp2(ptr, నమూనా, pglob, limitp);

	తిరిగి glob0(నమూనా, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
స్థిర పూర్ణాంకం
globexp2(స్థిరరాశి Char *ptr, స్థిరరాశి Char *నమూనా, glob_t *pglob,
    నిర్మాణం glob_lim *limitp)
{
	పూర్ణాంకం     i, rv;
	Char   *lm, *ls;
	స్థిరరాశి Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	కొరకు (lm = patbuf, pm = నమూనా; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	కొరకు (i = 0, pe = ++ptr; *pe; pe++)
		ఒకవేళ (*pe == LBRACKET) {
			/* Ignore everything between [] */
			కొరకు (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			ఒకవేళ (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} లేకపోతే ఒకవేళ (*pe == LBRACE)
			i++;
		లేకపోతే ఒకవేళ (*pe == RBRACE) {
			ఒకవేళ (i == 0)
				ఆపు;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	ఒకవేళ (i != 0 || *pe == EOS)
		తిరిగి glob0(patbuf, pglob, limitp);

	కొరకు (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		ఎంపిక (*pm) {
		స్థితి LBRACKET:
			/* Ignore everything between [] */
			కొరకు (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			ఒకవేళ (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			ఆపు;

		స్థితి LBRACE:
			i++;
			ఆపు;

		స్థితి RBRACE:
			ఒకవేళ (i) {
				i--;
				ఆపు;
			}
			/* FALLTHROUGH */
		స్థితి COMMA:
			ఒకవేళ (i && *pm == COMMA)
				ఆపు;
			లేకపోతే {
				/* Append the current string */
				కొరకు (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				కొరకు (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#నిర్వచితమైతే DEBUG
				qprintf("globexp2:", patbuf);
#అయితే_ముగింపు
				rv = globexp1(patbuf, pglob, limitp);
				ఒకవేళ (rv && rv != GLOB_NOMATCH)
					తిరిగి rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			ఆపు;

		అప్రమేయ:
			ఆపు;
		}
	}
	తిరిగి 0;
}



/*
 * expand tilde from the passwd file.
 */
స్థిర స్థిరరాశి Char *
globtilde(స్థిరరాశి Char *నమూనా, Char *patbuf, కొలత_t patbuf_len, glob_t *pglob)
{
	నిర్మాణం passwd *pwd;
	అక్షరం *h;
	స్థిరరాశి Char *p;
	Char *b, *eb;

	ఒకవేళ (*నమూనా != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		తిరిగి నమూనా;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	కొరకు (p = నమూనా + 1, h = (అక్షరం *) patbuf;
	    h < (అక్షరం *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#ఒకవేళ 0
	ఒకవేళ (h == (అక్షరం *)eb)
		తిరిగి what;
#అయితే_ముగింపు

	ఒకవేళ (((అక్షరం *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#ఒకవేళ 0
		ఒకవేళ (issetugid() != 0 || (h = getenv("HOME")) == ఖాళీ) {
#అయితే_ముగింపు
		ఒకవేళ ((getuid() != geteuid()) || (h = getenv("HOME")) == ఖాళీ) {
			ఒకవేళ ((pwd = getpwuid(getuid())) == ఖాళీ)
				తిరిగి నమూనా;
			లేకపోతే
				h = pwd->pw_dir;
		}
	} లేకపోతే {
		/*
		 * Expand a ~user
		 */
		ఒకవేళ ((pwd = getpwnam((అక్షరం*) patbuf)) == ఖాళీ)
			తిరిగి నమూనా;
		లేకపోతే
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	కొరకు (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	అయితే (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	తిరిగి patbuf;
}

స్థిర పూర్ణాంకం
g_strncmp(స్థిరరాశి Char *s1, స్థిరరాశి అక్షరం *s2, కొలత_t n)
{
	పూర్ణాంకం rv = 0;

	అయితే (n--) {
		rv = *(Char *)s1 - *(స్థిరరాశి గుర్తులేని అక్షరం *)s2++;
		ఒకవేళ (rv)
			ఆపు;
		ఒకవేళ (*s1++ == '\0')
			ఆపు;
	}
	తిరిగి rv;
}

స్థిర పూర్ణాంకం
g_charclass(స్థిరరాశి Char **patternp, Char **bufnextp)
{
	స్థిరరాశి Char *నమూనా = *patternp + 1;
	Char *bufnext = *bufnextp;
	స్థిరరాశి Char *colon;
	నిర్మాణం cclass *cc;
	కొలత_t len;

	ఒకవేళ ((colon = g_strchr(నమూనా, ':')) == ఖాళీ || colon[1] != ']')
		తిరిగి 1;	/* not a character class */

	len = (కొలత_t)(colon - నమూనా);
	కొరకు (cc = cclasses; cc->name != ఖాళీ; cc++) {
		ఒకవేళ (!g_strncmp(నమూనా, cc->name, len) && cc->name[len] == '\0')
			ఆపు;
	}
	ఒకవేళ (cc->name == ఖాళీ)
		తిరిగి -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	తిరిగి 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
స్థిర పూర్ణాంకం
glob0(స్థిరరాశి Char *నమూనా, glob_t *pglob, నిర్మాణం glob_lim *limitp)
{
	స్థిరరాశి Char *qpatnext;
	పూర్ణాంకం c, err;
	కొలత_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(నమూనా, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	అయితే ((c = *qpatnext++) != EOS) {
		ఎంపిక (c) {
		స్థితి LBRACKET:
			c = *qpatnext;
			ఒకవేళ (c == NOT)
				++qpatnext;
			ఒకవేళ (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == ఖాళీ) {
				*bufnext++ = LBRACKET;
				ఒకవేళ (c == NOT)
					--qpatnext;
				ఆపు;
			}
			*bufnext++ = M_సమితి;
			ఒకవేళ (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			చేయి {
				ఒకవేళ (c == LBRACKET && *qpatnext == ':') {
					చేయి {
						err = g_charclass(&qpatnext,
						    &bufnext);
						ఒకవేళ (err)
							ఆపు;
						c = *qpatnext++;
					} అయితే (c == LBRACKET && *qpatnext == ':');
					ఒకవేళ (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						తిరిగి GLOB_NOMATCH;
					ఒకవేళ (c == RBRACKET)
						ఆపు;
				}
				*bufnext++ = CHAR(c);
				ఒకవేళ (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} అయితే ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_చివర;
			ఆపు;
		స్థితి QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			ఆపు;
		స్థితి నక్షత్రం:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			ఒకవేళ (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			ఆపు;
		అప్రమేయ:
			*bufnext++ = CHAR(c);
			ఆపు;
		}
	}
	*bufnext = EOS;
#నిర్వచితమైతే DEBUG
	qprintf("glob0:", patbuf);
#అయితే_ముగింపు

	ఒకవేళ ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		తిరిగి(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	ఒకవేళ (pglob->gl_pathc == oldpathc) {
		ఒకవేళ ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			తిరిగి(globextend(నమూనా, pglob, limitp, ఖాళీ));
		లేకపోతే
			తిరిగి(GLOB_NOMATCH);
	}
	ఒకవేళ (!(pglob->gl_flags & GLOB_NOSORT)) {
		ఒకవేళ ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			నిర్మాణం glob_మార్గం_stat *మార్గం_stat;
			కొలత_t i;
			కొలత_t n = pglob->gl_pathc - oldpathc;
			కొలత_t o = pglob->gl_offs + oldpathc;

			ఒకవేళ ((మార్గం_stat = సున్నా_జ్ఞాపకం_ఇవ్వు(n, పరిమాణం(*మార్గం_stat))) == ఖాళీ)
				తిరిగి GLOB_NOSPACE;
			కొరకు (i = 0; i < n; i++) {
				మార్గం_stat[i].gps_మార్గం = pglob->gl_pathv[o + i];
				మార్గం_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(మార్గం_stat, n, పరిమాణం(*మార్గం_stat), compare_gps);
			కొరకు (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = మార్గం_stat[i].gps_మార్గం;
				pglob->gl_statv[o + i] = మార్గం_stat[i].gps_stat;
			}
			విడుదల(మార్గం_stat);
		} లేకపోతే {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, పరిమాణం(అక్షరం *),
			    compare);
		}
	}
	తిరిగి(0);
}

స్థిర పూర్ణాంకం
compare(స్థిరరాశి శూన్య *p, స్థిరరాశి శూన్య *q)
{
	తిరిగి(strcmp(*(అక్షరం **)p, *(అక్షరం **)q));
}

స్థిర పూర్ణాంకం
compare_gps(స్థిరరాశి శూన్య *_p, స్థిరరాశి శూన్య *_q)
{
	స్థిరరాశి నిర్మాణం glob_మార్గం_stat *p = (స్థిరరాశి నిర్మాణం glob_మార్గం_stat *)_p;
	స్థిరరాశి నిర్మాణం glob_మార్గం_stat *q = (స్థిరరాశి నిర్మాణం glob_మార్గం_stat *)_q;

	తిరిగి(strcmp(p->gps_మార్గం, q->gps_మార్గం));
}

స్థిర పూర్ణాంకం
glob1(Char *నమూనా, Char *నమూనా_చివరి, glob_t *pglob, నిర్మాణం glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	ఒకవేళ (*నమూనా == EOS)
		తిరిగి(0);
	తిరిగి(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    నమూనా, నమూనా_చివరి, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
స్థిర పూర్ణాంకం
glob2(Char *pathbuf, Char *pathbuf_చివరి, Char *pathend, Char *pathend_చివరి,
    Char *నమూనా, Char *నమూనా_చివరి, glob_t *pglob, నిర్మాణం glob_lim *limitp)
{
	నిర్మాణం stat sb;
	Char *p, *q;
	పూర్ణాంకం anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	కొరకు (anymeta = 0;;) {
		ఒకవేళ (*నమూనా == EOS) {		/* End of pattern? */
			*pathend = EOS;

			ఒకవేళ ((pglob->gl_flags & GLOB_హద్దు) &&
			    limitp->glim_stat++ >= GLOB_హద్దు_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				తిరిగి(GLOB_NOSPACE);
			}
			ఒకవేళ (g_lstat(pathbuf, &sb, pglob))
				తిరిగి(0);

			ఒకవేళ (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				ఒకవేళ (pathend+1 > pathend_చివరి)
					తిరిగి (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			తిరిగి(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = నమూనా;
		అయితే (*p != EOS && *p != SEP) {
			ఒకవేళ (ismeta(*p))
				anymeta = 1;
			ఒకవేళ (q+1 > pathend_చివరి)
				తిరిగి (1);
			*q++ = *p++;
		}

		ఒకవేళ (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			నమూనా = p;
			అయితే (*నమూనా == SEP) {
				ఒకవేళ (pathend+1 > pathend_చివరి)
					తిరిగి (1);
				*pathend++ = *నమూనా++;
			}
		} లేకపోతే
			/* Need expansion, recurse. */
			తిరిగి(glob3(pathbuf, pathbuf_చివరి, pathend,
			    pathend_చివరి, నమూనా, p, నమూనా_చివరి,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

స్థిర పూర్ణాంకం
glob3(Char *pathbuf, Char *pathbuf_చివరి, Char *pathend, Char *pathend_చివరి,
    Char *నమూనా, Char *restpattern, Char *restpattern_చివరి, glob_t *pglob,
    నిర్మాణం glob_lim *limitp)
{
	నిర్మాణం dirent *dp;
	DIR *dirp;
	పూర్ణాంకం err;
	అక్షరం buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	నిర్మాణం dirent *(*readdirfunc)(శూన్య *);

	ఒకవేళ (pathend > pathend_చివరి)
		తిరిగి (1);
	*pathend = EOS;
	errno = 0;

	ఒకవేళ ((dirp = g_opendir(pathbuf, pglob)) == ఖాళీ) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		ఒకవేళ (pglob->gl_errfunc) {
			ఒకవేళ (g_Ctoc(pathbuf, buf, పరిమాణం(buf)))
				తిరిగి(GLOB_ABORTED);
			ఒకవేళ (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				తిరిగి(GLOB_ABORTED);
		}
		తిరిగి(0);
	}

	err = 0;

	/* Search directory for matching names. */
	ఒకవేళ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	లేకపోతే
		readdirfunc = (నిర్మాణం dirent *(*)(శూన్య *))readdir;
	అయితే ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		ఒకవేళ ((pglob->gl_flags & GLOB_హద్దు) &&
		    limitp->glim_readdir++ >= GLOB_హద్దు_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			ఆపు;
		}

		/* Initial DOT must be matched literally. */
		ఒకవేళ (dp->d_name[0] == DOT && *నమూనా != DOT)
			కొనసాగు;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		అయితే (dc < pathend_చివరి && (*dc++ = *sc++) != EOS)
			;
		ఒకవేళ (dc >= pathend_చివరి) {
			*dc = EOS;
			err = 1;
			ఆపు;
		}

		ఒకవేళ (!సరిపోలిక(pathend, నమూనా, restpattern)) {
			*pathend = EOS;
			కొనసాగు;
		}
		err = glob2(pathbuf, pathbuf_చివరి, --dc, pathend_చివరి,
		    restpattern, restpattern_చివరి, pglob, limitp);
		ఒకవేళ (err)
			ఆపు;
	}

	ఒకవేళ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	లేకపోతే
		closedir(dirp);
	తిరిగి(err);
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
స్థిర పూర్ణాంకం
globextend(స్థిరరాశి Char *మార్గం, glob_t *pglob, నిర్మాణం glob_lim *limitp,
    నిర్మాణం stat *sb)
{
	అక్షరం **pathv;
	కొలత_t i, newn, len;
	అక్షరం *copy = ఖాళీ;
	స్థిరరాశి Char *p;
	నిర్మాణం stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	ఒకవేళ (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / పరిమాణం(*pathv) <= newn ||
	    SIZE_MAX / పరిమాణం(*statv) <= newn) {
 nospace:
		కొరకు (i = pglob->gl_offs; i < newn - 2; i++) {
			ఒకవేళ (pglob->gl_pathv && pglob->gl_pathv[i])
				విడుదల(pglob->gl_pathv[i]);
			ఒకవేళ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				విడుదల(pglob->gl_statv[i]);
		}
		విడుదల(pglob->gl_pathv);
		pglob->gl_pathv = ఖాళీ;
		విడుదల(pglob->gl_statv);
		pglob->gl_statv = ఖాళీ;
		తిరిగి(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, పరిమాణం(*pathv));
	ఒకవేళ (pathv == ఖాళీ)
		వెళ్ళు nospace;
	ఒకవేళ (pglob->gl_pathv == ఖాళీ && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		కొరకు (i = pglob->gl_offs; i > 0; i--)
			*--pathv = ఖాళీ;
	}
	pglob->gl_pathv = pathv;

	ఒకవేళ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, పరిమాణం(*statv));
		ఒకవేళ (statv == ఖాళీ)
			వెళ్ళు nospace;
		ఒకవేళ (pglob->gl_statv == ఖాళీ && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			కొరకు (i = pglob->gl_offs; i > 0; i--)
				*--statv = ఖాళీ;
		}
		pglob->gl_statv = statv;
		ఒకవేళ (sb == ఖాళీ)
			statv[pglob->gl_offs + pglob->gl_pathc] = ఖాళీ;
		లేకపోతే {
			limitp->glim_malloc += పరిమాణం(**statv);
			ఒకవేళ ((pglob->gl_flags & GLOB_హద్దు) &&
			    limitp->glim_malloc >= GLOB_హద్దు_MALLOC) {
				errno = 0;
				తిరిగి(GLOB_NOSPACE);
			}
			ఒకవేళ ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    జ్ఞాపకం_ఇవ్వు(పరిమాణం(**statv))) == ఖాళీ)
				వెళ్ళు copy_error;
			జ్ఞాపకం_నకలు(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    పరిమాణం(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = ఖాళీ;
	}

	కొరకు (p = మార్గం; *p++;)
		;
	len = (కొలత_t)(p - మార్గం);
	limitp->glim_malloc += len;
	ఒకవేళ ((copy = జ్ఞాపకం_ఇవ్వు(len)) != ఖాళీ) {
		ఒకవేళ (g_Ctoc(మార్గం, copy, len)) {
			విడుదల(copy);
			తిరిగి(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = ఖాళీ;

	ఒకవేళ ((pglob->gl_flags & GLOB_హద్దు) &&
	    (newn * పరిమాణం(*pathv)) + limitp->glim_malloc >
	    GLOB_హద్దు_MALLOC) {
		errno = 0;
		తిరిగి(GLOB_NOSPACE);
	}
 copy_error:
	తిరిగి(copy == ఖాళీ ? GLOB_NOSPACE : 0);
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
స్థిర పూర్ణాంకం
సరిపోలిక(Char *name, Char *pat, Char *patend)
{
	పూర్ణాంకం ok, negate_range;
	Char c, k;
	Char *nextp = ఖాళీ;
	Char *nextn = ఖాళీ;

loop:
	అయితే (pat < patend) {
		c = *pat++;
		ఎంపిక (c & M_ముసుగు) {
		స్థితి M_ALL:
			అయితే (pat < patend && (*pat & M_ముసుగు) == M_ALL)
				pat++;	/* eat consecutive '*' */
			ఒకవేళ (pat == patend)
				తిరిగి(1);
			ఒకవేళ (*name == EOS)
				తిరిగి(0);
			nextn = name + 1;
			nextp = pat - 1;
			ఆపు;
		స్థితి M_ONE:
			ఒకవేళ (*name++ == EOS)
				వెళ్ళు fail;
			ఆపు;
		స్థితి M_సమితి:
			ok = 0;
			ఒకవేళ ((k = *name++) == EOS)
				వెళ్ళు fail;
			ఒకవేళ ((negate_range = ((*pat & M_ముసుగు) == M_NOT)) != EOS)
				++pat;
			అయితే (((c = *pat++) & M_ముసుగు) != M_చివర) {
				ఒకవేళ ((c & M_ముసుగు) == M_CLASS) {
					Char idx = *pat & M_ముసుగు;
					ఒకవేళ (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				ఒకవేళ ((*pat & M_ముసుగు) == M_RNG) {
					ఒకవేళ (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} లేకపోతే ఒకవేళ (c == k)
					ok = 1;
			}
			ఒకవేళ (ok == negate_range)
				వెళ్ళు fail;
			ఆపు;
		అప్రమేయ:
			ఒకవేళ (*name++ != c)
				వెళ్ళు fail;
			ఆపు;
		}
	}
	ఒకవేళ (*name == EOS)
		తిరిగి(1);

fail:
	ఒకవేళ (nextn) {
		pat = nextp;
		name = nextn;
		వెళ్ళు loop;
	}
	తిరిగి(0);
}

/* Free allocated data belonging to a glob_t structure. */
శూన్య
globfree(glob_t *pglob)
{
	కొలత_t i;
	అక్షరం **pp;

	ఒకవేళ (pglob->gl_pathv != ఖాళీ) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		కొరకు (i = pglob->gl_pathc; i--; ++pp)
			విడుదల(*pp);
		విడుదల(pglob->gl_pathv);
		pglob->gl_pathv = ఖాళీ;
	}
	ఒకవేళ (pglob->gl_statv != ఖాళీ) {
		కొరకు (i = 0; i < pglob->gl_pathc; i++) {
			విడుదల(pglob->gl_statv[i]);
		}
		విడుదల(pglob->gl_statv);
		pglob->gl_statv = ఖాళీ;
	}
}

స్థిర DIR *
g_opendir(Char *str, glob_t *pglob)
{
	అక్షరం buf[PATH_MAX];

	ఒకవేళ (!*str)
		strlcpy(buf, ".", పరిమాణం buf);
	లేకపోతే {
		ఒకవేళ (g_Ctoc(str, buf, పరిమాణం(buf)))
			తిరిగి(ఖాళీ);
	}

	ఒకవేళ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		తిరిగి((*pglob->gl_opendir)(buf));

	తిరిగి(opendir(buf));
}

స్థిర పూర్ణాంకం
g_lstat(Char *fn, నిర్మాణం stat *sb, glob_t *pglob)
{
	అక్షరం buf[PATH_MAX];

	ఒకవేళ (g_Ctoc(fn, buf, పరిమాణం(buf)))
		తిరిగి(-1);
	ఒకవేళ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		తిరిగి((*pglob->gl_lstat)(buf, sb));
	తిరిగి(lstat(buf, sb));
}

స్థిర పూర్ణాంకం
g_stat(Char *fn, నిర్మాణం stat *sb, glob_t *pglob)
{
	అక్షరం buf[PATH_MAX];

	ఒకవేళ (g_Ctoc(fn, buf, పరిమాణం(buf)))
		తిరిగి(-1);
	ఒకవేళ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		తిరిగి((*pglob->gl_stat)(buf, sb));
	తిరిగి(stat(buf, sb));
}

స్థిర Char *
g_strchr(స్థిరరాశి Char *str, పూర్ణాంకం ch)
{
	చేయి {
		ఒకవేళ (*str == ch)
			తిరిగి ((Char *)str);
	} అయితే (*str++);
	తిరిగి (ఖాళీ);
}

స్థిర పూర్ణాంకం
g_Ctoc(స్థిరరాశి Char *str, అక్షరం *buf, కొలత_t len)
{

	అయితే (len--) {
		ఒకవేళ ((*buf++ = *str++) == EOS)
			తిరిగి (0);
	}
	తిరిగి (1);
}

#నిర్వచితమైతే DEBUG
స్థిర శూన్య
qprintf(స్థిరరాశి అక్షరం *str, Char *s)
{
	Char *p;

	(శూన్య)రాయి("%s:\n", str);
	కొరకు (p = s; *p; p++)
		(శూన్య)రాయి("%c", CHAR(*p));
	(శూన్య)రాయి("\n");
	కొరకు (p = s; *p; p++)
		(శూన్య)రాయి("%c", *p & M_PROTECT ? '"' : ' ');
	(శూన్య)రాయి("\n");
	కొరకు (p = s; *p; p++)
		(శూన్య)రాయి("%c", ismeta(*p) ? '_' : ' ');
	(శూన్య)రాయి("\n");
}
#అయితే_ముగింపు

#అయితే_ముగింపు /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
