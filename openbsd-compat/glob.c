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

#அந்தர்பாவ "includes.h"
#அந்தர்பாவ "glob.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>

#அந்தர்பாவ <dirent.h>
#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#எனில் !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#அந்தர்பாவ "charclass.h"

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

வகைவரை u_short Char;

#இல்லையெனில்

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

வகைவரை எழுத்து Char;

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

கட்டமைப்பு glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

கட்டமைப்பு glob_path_stat {
	எழுத்து		*gps_path;
	கட்டமைப்பு stat	*gps_stat;
};

நிலையான முழு	 compare(மாறிலி வெறுமை *, மாறிலி வெறுமை *);
நிலையான முழு	 compare_gps(மாறிலி வெறுமை *, மாறிலி வெறுமை *);
நிலையான முழு	 g_Ctoc(மாறிலி Char *, எழுத்து *, size_t);
நிலையான முழு	 g_lstat(Char *, கட்டமைப்பு stat *, glob_t *);
நிலையான DIR	*g_opendir(Char *, glob_t *);
நிலையான Char	*g_strchr(மாறிலி Char *, முழு);
நிலையான முழு	 g_strncmp(மாறிலி Char *, மாறிலி எழுத்து *, size_t);
நிலையான முழு	 g_stat(Char *, கட்டமைப்பு stat *, glob_t *);
நிலையான முழு	 glob0(மாறிலி Char *, glob_t *, கட்டமைப்பு glob_lim *);
நிலையான முழு	 glob1(Char *, Char *, glob_t *, கட்டமைப்பு glob_lim *);
நிலையான முழு	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, கட்டமைப்பு glob_lim *);
நிலையான முழு	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, கட்டமைப்பு glob_lim *);
நிலையான முழு	 globextend(மாறிலி Char *, glob_t *, கட்டமைப்பு glob_lim *,
		    கட்டமைப்பு stat *);
நிலையான மாறிலி Char *
		 globtilde(மாறிலி Char *, Char *, size_t, glob_t *);
நிலையான முழு	 globexp1(மாறிலி Char *, glob_t *, கட்டமைப்பு glob_lim *);
நிலையான முழு	 globexp2(மாறிலி Char *, மாறிலி Char *, glob_t *,
		    கட்டமைப்பு glob_lim *);
நிலையான முழு	 match(Char *, Char *, Char *);
#ifdef DEBUG
நிலையான வெறுமை	 qprintf(மாறிலி எழுத்து *, Char *);
#endif

முழு
glob(மாறிலி எழுத்து *pattern, முழு flags, முழு (*errfunc)(மாறிலி எழுத்து *, முழு),
    glob_t *pglob)
{
	மாறிலி u_char *patnext;
	முழு c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	கட்டமைப்பு glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	எனில் (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = வெற்று;
		pglob->gl_statv = வெற்று;
		எனில் (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	எனில் (strnlen(pattern, PATH_MAX) == PATH_MAX)
		திரும்பு(GLOB_NOMATCH);

	எனில் (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		திரும்பு GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	எனில் (flags & GLOB_NOESCAPE)
		போது (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	இல்லையெனில் {
		/* Protect the quoted characters. */
		போது (bufnext < bufend && (c = *patnext++) != EOS)
			எனில் (c == QUOTE) {
				எனில் ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} இல்லையெனில்
				*bufnext++ = c;
	}
	*bufnext = EOS;

	எனில் (flags & GLOB_BRACE)
		திரும்பு globexp1(patbuf, pglob, &limit);
	இல்லையெனில்
		திரும்பு glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
நிலையான முழு
globexp1(மாறிலி Char *pattern, glob_t *pglob, கட்டமைப்பு glob_lim *limitp)
{
	மாறிலி Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	எனில் (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		திரும்பு glob0(pattern, pglob, limitp);

	எனில் ((ptr = (மாறிலி Char *) g_strchr(ptr, LBRACE)) != வெற்று)
		திரும்பு globexp2(ptr, pattern, pglob, limitp);

	திரும்பு glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
நிலையான முழு
globexp2(மாறிலி Char *ptr, மாறிலி Char *pattern, glob_t *pglob,
    கட்டமைப்பு glob_lim *limitp)
{
	முழு     i, rv;
	Char   *lm, *ls;
	மாறிலி Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	க்கு (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	க்கு (i = 0, pe = ++ptr; *pe; pe++)
		எனில் (*pe == LBRACKET) {
			/* Ignore everything between [] */
			க்கு (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			எனில் (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} இல்லையெனில் எனில் (*pe == LBRACE)
			i++;
		இல்லையெனில் எனில் (*pe == RBRACE) {
			எனில் (i == 0)
				நிறுத்து;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	எனில் (i != 0 || *pe == EOS)
		திரும்பு glob0(patbuf, pglob, limitp);

	க்கு (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		தேர்வு (*pm) {
		நிலை LBRACKET:
			/* Ignore everything between [] */
			க்கு (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			எனில் (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			நிறுத்து;

		நிலை LBRACE:
			i++;
			நிறுத்து;

		நிலை RBRACE:
			எனில் (i) {
				i--;
				நிறுத்து;
			}
			/* FALLTHROUGH */
		நிலை COMMA:
			எனில் (i && *pm == COMMA)
				நிறுத்து;
			இல்லையெனில் {
				/* Append the current string */
				க்கு (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				க்கு (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				எனில் (rv && rv != GLOB_NOMATCH)
					திரும்பு rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			நிறுத்து;

		இயல்பு:
			நிறுத்து;
		}
	}
	திரும்பு 0;
}



/*
 * expand tilde from the passwd file.
 */
நிலையான மாறிலி Char *
globtilde(மாறிலி Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	கட்டமைப்பு passwd *pwd;
	எழுத்து *h;
	மாறிலி Char *p;
	Char *b, *eb;

	எனில் (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		திரும்பு pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	க்கு (p = pattern + 1, h = (எழுத்து *) patbuf;
	    h < (எழுத்து *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#எனில் 0
	எனில் (h == (எழுத்து *)eb)
		திரும்பு what;
#endif

	எனில் (((எழுத்து *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#எனில் 0
		எனில் (issetugid() != 0 || (h = getenv("HOME")) == வெற்று) {
#endif
		எனில் ((getuid() != geteuid()) || (h = getenv("HOME")) == வெற்று) {
			எனில் ((pwd = getpwuid(getuid())) == வெற்று)
				திரும்பு pattern;
			இல்லையெனில்
				h = pwd->pw_dir;
		}
	} இல்லையெனில் {
		/*
		 * Expand a ~user
		 */
		எனில் ((pwd = getpwnam((எழுத்து*) patbuf)) == வெற்று)
			திரும்பு pattern;
		இல்லையெனில்
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	க்கு (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	போது (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	திரும்பு patbuf;
}

நிலையான முழு
g_strncmp(மாறிலி Char *s1, மாறிலி எழுத்து *s2, size_t n)
{
	முழு rv = 0;

	போது (n--) {
		rv = *(Char *)s1 - *(மாறிலி unsigned எழுத்து *)s2++;
		எனில் (rv)
			நிறுத்து;
		எனில் (*s1++ == '\0')
			நிறுத்து;
	}
	திரும்பு rv;
}

நிலையான முழு
g_charclass(மாறிலி Char **patternp, Char **bufnextp)
{
	மாறிலி Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	மாறிலி Char *colon;
	கட்டமைப்பு cclass *cc;
	size_t len;

	எனில் ((colon = g_strchr(pattern, ':')) == வெற்று || colon[1] != ']')
		திரும்பு 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	க்கு (cc = cclasses; cc->name != வெற்று; cc++) {
		எனில் (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			நிறுத்து;
	}
	எனில் (cc->name == வெற்று)
		திரும்பு -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	திரும்பு 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
நிலையான முழு
glob0(மாறிலி Char *pattern, glob_t *pglob, கட்டமைப்பு glob_lim *limitp)
{
	மாறிலி Char *qpatnext;
	முழு c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	போது ((c = *qpatnext++) != EOS) {
		தேர்வு (c) {
		நிலை LBRACKET:
			c = *qpatnext;
			எனில் (c == NOT)
				++qpatnext;
			எனில் (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == வெற்று) {
				*bufnext++ = LBRACKET;
				எனில் (c == NOT)
					--qpatnext;
				நிறுத்து;
			}
			*bufnext++ = M_SET;
			எனில் (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			செய் {
				எனில் (c == LBRACKET && *qpatnext == ':') {
					செய் {
						err = g_charclass(&qpatnext,
						    &bufnext);
						எனில் (err)
							நிறுத்து;
						c = *qpatnext++;
					} போது (c == LBRACKET && *qpatnext == ':');
					எனில் (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						திரும்பு GLOB_NOMATCH;
					எனில் (c == RBRACKET)
						நிறுத்து;
				}
				*bufnext++ = CHAR(c);
				எனில் (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} போது ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			நிறுத்து;
		நிலை QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			நிறுத்து;
		நிலை STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			எனில் (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			நிறுத்து;
		இயல்பு:
			*bufnext++ = CHAR(c);
			நிறுத்து;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	எனில் ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		திரும்பு(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	எனில் (pglob->gl_pathc == oldpathc) {
		எனில் ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			திரும்பு(globextend(pattern, pglob, limitp, வெற்று));
		இல்லையெனில்
			திரும்பு(GLOB_NOMATCH);
	}
	எனில் (!(pglob->gl_flags & GLOB_NOSORT)) {
		எனில் ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			கட்டமைப்பு glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			எனில் ((path_stat = calloc(n, அளவு(*path_stat))) == வெற்று)
				திரும்பு GLOB_NOSPACE;
			க்கு (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, அளவு(*path_stat), compare_gps);
			க்கு (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			விடுவி(path_stat);
		} இல்லையெனில் {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, அளவு(எழுத்து *),
			    compare);
		}
	}
	திரும்பு(0);
}

நிலையான முழு
compare(மாறிலி வெறுமை *p, மாறிலி வெறுமை *q)
{
	திரும்பு(strcmp(*(எழுத்து **)p, *(எழுத்து **)q));
}

நிலையான முழு
compare_gps(மாறிலி வெறுமை *_p, மாறிலி வெறுமை *_q)
{
	மாறிலி கட்டமைப்பு glob_path_stat *p = (மாறிலி கட்டமைப்பு glob_path_stat *)_p;
	மாறிலி கட்டமைப்பு glob_path_stat *q = (மாறிலி கட்டமைப்பு glob_path_stat *)_q;

	திரும்பு(strcmp(p->gps_path, q->gps_path));
}

நிலையான முழு
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, கட்டமைப்பு glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	எனில் (*pattern == EOS)
		திரும்பு(0);
	திரும்பு(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
நிலையான முழு
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, கட்டமைப்பு glob_lim *limitp)
{
	கட்டமைப்பு stat sb;
	Char *p, *q;
	முழு anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	க்கு (anymeta = 0;;) {
		எனில் (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			எனில் ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				திரும்பு(GLOB_NOSPACE);
			}
			எனில் (g_lstat(pathbuf, &sb, pglob))
				திரும்பு(0);

			எனில் (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				எனில் (pathend+1 > pathend_last)
					திரும்பு (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			திரும்பு(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		போது (*p != EOS && *p != SEP) {
			எனில் (ismeta(*p))
				anymeta = 1;
			எனில் (q+1 > pathend_last)
				திரும்பு (1);
			*q++ = *p++;
		}

		எனில் (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			போது (*pattern == SEP) {
				எனில் (pathend+1 > pathend_last)
					திரும்பு (1);
				*pathend++ = *pattern++;
			}
		} இல்லையெனில்
			/* Need expansion, recurse. */
			திரும்பு(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

நிலையான முழு
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    கட்டமைப்பு glob_lim *limitp)
{
	கட்டமைப்பு dirent *dp;
	DIR *dirp;
	முழு err;
	எழுத்து buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	கட்டமைப்பு dirent *(*readdirfunc)(வெறுமை *);

	எனில் (pathend > pathend_last)
		திரும்பு (1);
	*pathend = EOS;
	errno = 0;

	எனில் ((dirp = g_opendir(pathbuf, pglob)) == வெற்று) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		எனில் (pglob->gl_errfunc) {
			எனில் (g_Ctoc(pathbuf, buf, அளவு(buf)))
				திரும்பு(GLOB_ABORTED);
			எனில் (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				திரும்பு(GLOB_ABORTED);
		}
		திரும்பு(0);
	}

	err = 0;

	/* Search directory for matching names. */
	எனில் (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	இல்லையெனில்
		readdirfunc = (கட்டமைப்பு dirent *(*)(வெறுமை *))readdir;
	போது ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		எனில் ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			நிறுத்து;
		}

		/* Initial DOT must be matched literally. */
		எனில் (dp->d_name[0] == DOT && *pattern != DOT)
			தொடர்;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		போது (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		எனில் (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			நிறுத்து;
		}

		எனில் (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			தொடர்;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		எனில் (err)
			நிறுத்து;
	}

	எனில் (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	இல்லையெனில்
		closedir(dirp);
	திரும்பு(err);
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
நிலையான முழு
globextend(மாறிலி Char *path, glob_t *pglob, கட்டமைப்பு glob_lim *limitp,
    கட்டமைப்பு stat *sb)
{
	எழுத்து **pathv;
	size_t i, newn, len;
	எழுத்து *copy = வெற்று;
	மாறிலி Char *p;
	கட்டமைப்பு stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	எனில் (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / அளவு(*pathv) <= newn ||
	    SIZE_MAX / அளவு(*statv) <= newn) {
 nospace:
		க்கு (i = pglob->gl_offs; i < newn - 2; i++) {
			எனில் (pglob->gl_pathv && pglob->gl_pathv[i])
				விடுவி(pglob->gl_pathv[i]);
			எனில் ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				விடுவி(pglob->gl_statv[i]);
		}
		விடுவி(pglob->gl_pathv);
		pglob->gl_pathv = வெற்று;
		விடுவி(pglob->gl_statv);
		pglob->gl_statv = வெற்று;
		திரும்பு(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, அளவு(*pathv));
	எனில் (pathv == வெற்று)
		செல் nospace;
	எனில் (pglob->gl_pathv == வெற்று && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		க்கு (i = pglob->gl_offs; i > 0; i--)
			*--pathv = வெற்று;
	}
	pglob->gl_pathv = pathv;

	எனில் ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, அளவு(*statv));
		எனில் (statv == வெற்று)
			செல் nospace;
		எனில் (pglob->gl_statv == வெற்று && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			க்கு (i = pglob->gl_offs; i > 0; i--)
				*--statv = வெற்று;
		}
		pglob->gl_statv = statv;
		எனில் (sb == வெற்று)
			statv[pglob->gl_offs + pglob->gl_pathc] = வெற்று;
		இல்லையெனில் {
			limitp->glim_malloc += அளவு(**statv);
			எனில் ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				திரும்பு(GLOB_NOSPACE);
			}
			எனில் ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(அளவு(**statv))) == வெற்று)
				செல் copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    அளவு(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = வெற்று;
	}

	க்கு (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	எனில் ((copy = malloc(len)) != வெற்று) {
		எனில் (g_Ctoc(path, copy, len)) {
			விடுவி(copy);
			திரும்பு(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = வெற்று;

	எனில் ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * அளவு(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		திரும்பு(GLOB_NOSPACE);
	}
 copy_error:
	திரும்பு(copy == வெற்று ? GLOB_NOSPACE : 0);
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
நிலையான முழு
match(Char *name, Char *pat, Char *patend)
{
	முழு ok, negate_range;
	Char c, k;
	Char *nextp = வெற்று;
	Char *nextn = வெற்று;

loop:
	போது (pat < patend) {
		c = *pat++;
		தேர்வு (c & M_MASK) {
		நிலை M_ALL:
			போது (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			எனில் (pat == patend)
				திரும்பு(1);
			எனில் (*name == EOS)
				திரும்பு(0);
			nextn = name + 1;
			nextp = pat - 1;
			நிறுத்து;
		நிலை M_ONE:
			எனில் (*name++ == EOS)
				செல் fail;
			நிறுத்து;
		நிலை M_SET:
			ok = 0;
			எனில் ((k = *name++) == EOS)
				செல் fail;
			எனில் ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			போது (((c = *pat++) & M_MASK) != M_END) {
				எனில் ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					எனில் (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				எனில் ((*pat & M_MASK) == M_RNG) {
					எனில் (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} இல்லையெனில் எனில் (c == k)
					ok = 1;
			}
			எனில் (ok == negate_range)
				செல் fail;
			நிறுத்து;
		இயல்பு:
			எனில் (*name++ != c)
				செல் fail;
			நிறுத்து;
		}
	}
	எனில் (*name == EOS)
		திரும்பு(1);

fail:
	எனில் (nextn) {
		pat = nextp;
		name = nextn;
		செல் loop;
	}
	திரும்பு(0);
}

/* Free allocated data belonging to a glob_t structure. */
வெறுமை
globfree(glob_t *pglob)
{
	size_t i;
	எழுத்து **pp;

	எனில் (pglob->gl_pathv != வெற்று) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		க்கு (i = pglob->gl_pathc; i--; ++pp)
			விடுவி(*pp);
		விடுவி(pglob->gl_pathv);
		pglob->gl_pathv = வெற்று;
	}
	எனில் (pglob->gl_statv != வெற்று) {
		க்கு (i = 0; i < pglob->gl_pathc; i++) {
			விடுவி(pglob->gl_statv[i]);
		}
		விடுவி(pglob->gl_statv);
		pglob->gl_statv = வெற்று;
	}
}

நிலையான DIR *
g_opendir(Char *str, glob_t *pglob)
{
	எழுத்து buf[PATH_MAX];

	எனில் (!*str)
		strlcpy(buf, ".", அளவு buf);
	இல்லையெனில் {
		எனில் (g_Ctoc(str, buf, அளவு(buf)))
			திரும்பு(வெற்று);
	}

	எனில் (pglob->gl_flags & GLOB_ALTDIRFUNC)
		திரும்பு((*pglob->gl_opendir)(buf));

	திரும்பு(opendir(buf));
}

நிலையான முழு
g_lstat(Char *fn, கட்டமைப்பு stat *sb, glob_t *pglob)
{
	எழுத்து buf[PATH_MAX];

	எனில் (g_Ctoc(fn, buf, அளவு(buf)))
		திரும்பு(-1);
	எனில் (pglob->gl_flags & GLOB_ALTDIRFUNC)
		திரும்பு((*pglob->gl_lstat)(buf, sb));
	திரும்பு(lstat(buf, sb));
}

நிலையான முழு
g_stat(Char *fn, கட்டமைப்பு stat *sb, glob_t *pglob)
{
	எழுத்து buf[PATH_MAX];

	எனில் (g_Ctoc(fn, buf, அளவு(buf)))
		திரும்பு(-1);
	எனில் (pglob->gl_flags & GLOB_ALTDIRFUNC)
		திரும்பு((*pglob->gl_stat)(buf, sb));
	திரும்பு(stat(buf, sb));
}

நிலையான Char *
g_strchr(மாறிலி Char *str, முழு ch)
{
	செய் {
		எனில் (*str == ch)
			திரும்பு ((Char *)str);
	} போது (*str++);
	திரும்பு (வெற்று);
}

நிலையான முழு
g_Ctoc(மாறிலி Char *str, எழுத்து *buf, size_t len)
{

	போது (len--) {
		எனில் ((*buf++ = *str++) == EOS)
			திரும்பு (0);
	}
	திரும்பு (1);
}

#ifdef DEBUG
நிலையான வெறுமை
qprintf(மாறிலி எழுத்து *str, Char *s)
{
	Char *p;

	(வெறுமை)printf("%s:\n", str);
	க்கு (p = s; *p; p++)
		(வெறுமை)printf("%c", CHAR(*p));
	(வெறுமை)printf("\n");
	க்கு (p = s; *p; p++)
		(வெறுமை)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(வெறுமை)printf("\n");
	க்கு (p = s; *p; p++)
		(வெறுமை)printf("%c", ismeta(*p) ? '_' : ' ');
	(வெறுமை)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
