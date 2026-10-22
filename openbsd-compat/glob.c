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

#അന്തര്ഭാവ "includes.h"
#അന്തര്ഭാവ "glob.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <dirent.h>
#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#എങ്കിൽ !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#അന്തര്ഭാവ "charclass.h"

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

തരനിർവചനം u_short Char;

#അല്ലെങ്കിൽ

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

തരനിർവചനം അക്ഷരം Char;

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

ഘടന glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

ഘടന glob_path_stat {
	അക്ഷരം		*gps_path;
	ഘടന stat	*gps_stat;
};

സ്ഥിതം പൂർണ്ണസംഖ്യ	 compare(സ്ഥിരം ശൂന്യം *, സ്ഥിരം ശൂന്യം *);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 compare_gps(സ്ഥിരം ശൂന്യം *, സ്ഥിരം ശൂന്യം *);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 g_Ctoc(സ്ഥിരം Char *, അക്ഷരം *, size_t);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 g_lstat(Char *, ഘടന stat *, glob_t *);
സ്ഥിതം DIR	*g_opendir(Char *, glob_t *);
സ്ഥിതം Char	*g_strchr(സ്ഥിരം Char *, പൂർണ്ണസംഖ്യ);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 g_strncmp(സ്ഥിരം Char *, സ്ഥിരം അക്ഷരം *, size_t);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 g_stat(Char *, ഘടന stat *, glob_t *);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 glob0(സ്ഥിരം Char *, glob_t *, ഘടന glob_lim *);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 glob1(Char *, Char *, glob_t *, ഘടന glob_lim *);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, ഘടന glob_lim *);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, ഘടന glob_lim *);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 globextend(സ്ഥിരം Char *, glob_t *, ഘടന glob_lim *,
		    ഘടന stat *);
സ്ഥിതം സ്ഥിരം Char *
		 globtilde(സ്ഥിരം Char *, Char *, size_t, glob_t *);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 globexp1(സ്ഥിരം Char *, glob_t *, ഘടന glob_lim *);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 globexp2(സ്ഥിരം Char *, സ്ഥിരം Char *, glob_t *,
		    ഘടന glob_lim *);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 match(Char *, Char *, Char *);
#ifdef DEBUG
സ്ഥിതം ശൂന്യം	 qprintf(സ്ഥിരം അക്ഷരം *, Char *);
#endif

പൂർണ്ണസംഖ്യ
glob(സ്ഥിരം അക്ഷരം *pattern, പൂർണ്ണസംഖ്യ flags, പൂർണ്ണസംഖ്യ (*errfunc)(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ),
    glob_t *pglob)
{
	സ്ഥിരം u_char *patnext;
	പൂർണ്ണസംഖ്യ c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	ഘടന glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	എങ്കിൽ (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = ശൂന്യ;
		pglob->gl_statv = ശൂന്യ;
		എങ്കിൽ (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	എങ്കിൽ (strnlen(pattern, PATH_MAX) == PATH_MAX)
		തിരികെ(GLOB_NOMATCH);

	എങ്കിൽ (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		തിരികെ GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	എങ്കിൽ (flags & GLOB_NOESCAPE)
		ആകുമ്പോൾ (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	അല്ലെങ്കിൽ {
		/* Protect the quoted characters. */
		ആകുമ്പോൾ (bufnext < bufend && (c = *patnext++) != EOS)
			എങ്കിൽ (c == QUOTE) {
				എങ്കിൽ ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} അല്ലെങ്കിൽ
				*bufnext++ = c;
	}
	*bufnext = EOS;

	എങ്കിൽ (flags & GLOB_BRACE)
		തിരികെ globexp1(patbuf, pglob, &limit);
	അല്ലെങ്കിൽ
		തിരികെ glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
globexp1(സ്ഥിരം Char *pattern, glob_t *pglob, ഘടന glob_lim *limitp)
{
	സ്ഥിരം Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	എങ്കിൽ (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		തിരികെ glob0(pattern, pglob, limitp);

	എങ്കിൽ ((ptr = (സ്ഥിരം Char *) g_strchr(ptr, LBRACE)) != ശൂന്യ)
		തിരികെ globexp2(ptr, pattern, pglob, limitp);

	തിരികെ glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
globexp2(സ്ഥിരം Char *ptr, സ്ഥിരം Char *pattern, glob_t *pglob,
    ഘടന glob_lim *limitp)
{
	പൂർണ്ണസംഖ്യ     i, rv;
	Char   *lm, *ls;
	സ്ഥിരം Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	വേണ്ടി (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	വേണ്ടി (i = 0, pe = ++ptr; *pe; pe++)
		എങ്കിൽ (*pe == LBRACKET) {
			/* Ignore everything between [] */
			വേണ്ടി (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			എങ്കിൽ (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (*pe == LBRACE)
			i++;
		അല്ലെങ്കിൽ എങ്കിൽ (*pe == RBRACE) {
			എങ്കിൽ (i == 0)
				നിർത്തുക;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	എങ്കിൽ (i != 0 || *pe == EOS)
		തിരികെ glob0(patbuf, pglob, limitp);

	വേണ്ടി (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		തിരഞ്ഞെടുപ്പ് (*pm) {
		അവസ്ഥ LBRACKET:
			/* Ignore everything between [] */
			വേണ്ടി (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			എങ്കിൽ (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			നിർത്തുക;

		അവസ്ഥ LBRACE:
			i++;
			നിർത്തുക;

		അവസ്ഥ RBRACE:
			എങ്കിൽ (i) {
				i--;
				നിർത്തുക;
			}
			/* FALLTHROUGH */
		അവസ്ഥ COMMA:
			എങ്കിൽ (i && *pm == COMMA)
				നിർത്തുക;
			അല്ലെങ്കിൽ {
				/* Append the current string */
				വേണ്ടി (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				വേണ്ടി (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				എങ്കിൽ (rv && rv != GLOB_NOMATCH)
					തിരികെ rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			നിർത്തുക;

		സ്ഥിരസ്ഥിതി:
			നിർത്തുക;
		}
	}
	തിരികെ 0;
}



/*
 * expand tilde from the passwd file.
 */
സ്ഥിതം സ്ഥിരം Char *
globtilde(സ്ഥിരം Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	ഘടന passwd *pwd;
	അക്ഷരം *h;
	സ്ഥിരം Char *p;
	Char *b, *eb;

	എങ്കിൽ (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		തിരികെ pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	വേണ്ടി (p = pattern + 1, h = (അക്ഷരം *) patbuf;
	    h < (അക്ഷരം *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#എങ്കിൽ 0
	എങ്കിൽ (h == (അക്ഷരം *)eb)
		തിരികെ what;
#endif

	എങ്കിൽ (((അക്ഷരം *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#എങ്കിൽ 0
		എങ്കിൽ (issetugid() != 0 || (h = getenv("HOME")) == ശൂന്യ) {
#endif
		എങ്കിൽ ((getuid() != geteuid()) || (h = getenv("HOME")) == ശൂന്യ) {
			എങ്കിൽ ((pwd = getpwuid(getuid())) == ശൂന്യ)
				തിരികെ pattern;
			അല്ലെങ്കിൽ
				h = pwd->pw_dir;
		}
	} അല്ലെങ്കിൽ {
		/*
		 * Expand a ~user
		 */
		എങ്കിൽ ((pwd = getpwnam((അക്ഷരം*) patbuf)) == ശൂന്യ)
			തിരികെ pattern;
		അല്ലെങ്കിൽ
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	വേണ്ടി (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	ആകുമ്പോൾ (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	തിരികെ patbuf;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
g_strncmp(സ്ഥിരം Char *s1, സ്ഥിരം അക്ഷരം *s2, size_t n)
{
	പൂർണ്ണസംഖ്യ rv = 0;

	ആകുമ്പോൾ (n--) {
		rv = *(Char *)s1 - *(സ്ഥിരം unsigned അക്ഷരം *)s2++;
		എങ്കിൽ (rv)
			നിർത്തുക;
		എങ്കിൽ (*s1++ == '\0')
			നിർത്തുക;
	}
	തിരികെ rv;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
g_charclass(സ്ഥിരം Char **patternp, Char **bufnextp)
{
	സ്ഥിരം Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	സ്ഥിരം Char *colon;
	ഘടന cclass *cc;
	size_t len;

	എങ്കിൽ ((colon = g_strchr(pattern, ':')) == ശൂന്യ || colon[1] != ']')
		തിരികെ 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	വേണ്ടി (cc = cclasses; cc->name != ശൂന്യ; cc++) {
		എങ്കിൽ (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			നിർത്തുക;
	}
	എങ്കിൽ (cc->name == ശൂന്യ)
		തിരികെ -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	തിരികെ 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
glob0(സ്ഥിരം Char *pattern, glob_t *pglob, ഘടന glob_lim *limitp)
{
	സ്ഥിരം Char *qpatnext;
	പൂർണ്ണസംഖ്യ c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	ആകുമ്പോൾ ((c = *qpatnext++) != EOS) {
		തിരഞ്ഞെടുപ്പ് (c) {
		അവസ്ഥ LBRACKET:
			c = *qpatnext;
			എങ്കിൽ (c == NOT)
				++qpatnext;
			എങ്കിൽ (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == ശൂന്യ) {
				*bufnext++ = LBRACKET;
				എങ്കിൽ (c == NOT)
					--qpatnext;
				നിർത്തുക;
			}
			*bufnext++ = M_SET;
			എങ്കിൽ (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			ചെയ്യുക {
				എങ്കിൽ (c == LBRACKET && *qpatnext == ':') {
					ചെയ്യുക {
						err = g_charclass(&qpatnext,
						    &bufnext);
						എങ്കിൽ (err)
							നിർത്തുക;
						c = *qpatnext++;
					} ആകുമ്പോൾ (c == LBRACKET && *qpatnext == ':');
					എങ്കിൽ (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						തിരികെ GLOB_NOMATCH;
					എങ്കിൽ (c == RBRACKET)
						നിർത്തുക;
				}
				*bufnext++ = CHAR(c);
				എങ്കിൽ (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} ആകുമ്പോൾ ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			നിർത്തുക;
		അവസ്ഥ QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			നിർത്തുക;
		അവസ്ഥ STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			എങ്കിൽ (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			*bufnext++ = CHAR(c);
			നിർത്തുക;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	എങ്കിൽ ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		തിരികെ(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	എങ്കിൽ (pglob->gl_pathc == oldpathc) {
		എങ്കിൽ ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			തിരികെ(globextend(pattern, pglob, limitp, ശൂന്യ));
		അല്ലെങ്കിൽ
			തിരികെ(GLOB_NOMATCH);
	}
	എങ്കിൽ (!(pglob->gl_flags & GLOB_NOSORT)) {
		എങ്കിൽ ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			ഘടന glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			എങ്കിൽ ((path_stat = calloc(n, വലുപ്പം(*path_stat))) == ശൂന്യ)
				തിരികെ GLOB_NOSPACE;
			വേണ്ടി (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, വലുപ്പം(*path_stat), compare_gps);
			വേണ്ടി (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			സ്വതന്ത്രം(path_stat);
		} അല്ലെങ്കിൽ {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, വലുപ്പം(അക്ഷരം *),
			    compare);
		}
	}
	തിരികെ(0);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
compare(സ്ഥിരം ശൂന്യം *p, സ്ഥിരം ശൂന്യം *q)
{
	തിരികെ(strcmp(*(അക്ഷരം **)p, *(അക്ഷരം **)q));
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
compare_gps(സ്ഥിരം ശൂന്യം *_p, സ്ഥിരം ശൂന്യം *_q)
{
	സ്ഥിരം ഘടന glob_path_stat *p = (സ്ഥിരം ഘടന glob_path_stat *)_p;
	സ്ഥിരം ഘടന glob_path_stat *q = (സ്ഥിരം ഘടന glob_path_stat *)_q;

	തിരികെ(strcmp(p->gps_path, q->gps_path));
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, ഘടന glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	എങ്കിൽ (*pattern == EOS)
		തിരികെ(0);
	തിരികെ(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, ഘടന glob_lim *limitp)
{
	ഘടന stat sb;
	Char *p, *q;
	പൂർണ്ണസംഖ്യ anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	വേണ്ടി (anymeta = 0;;) {
		എങ്കിൽ (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			എങ്കിൽ ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				തിരികെ(GLOB_NOSPACE);
			}
			എങ്കിൽ (g_lstat(pathbuf, &sb, pglob))
				തിരികെ(0);

			എങ്കിൽ (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				എങ്കിൽ (pathend+1 > pathend_last)
					തിരികെ (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			തിരികെ(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		ആകുമ്പോൾ (*p != EOS && *p != SEP) {
			എങ്കിൽ (ismeta(*p))
				anymeta = 1;
			എങ്കിൽ (q+1 > pathend_last)
				തിരികെ (1);
			*q++ = *p++;
		}

		എങ്കിൽ (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			ആകുമ്പോൾ (*pattern == SEP) {
				എങ്കിൽ (pathend+1 > pathend_last)
					തിരികെ (1);
				*pathend++ = *pattern++;
			}
		} അല്ലെങ്കിൽ
			/* Need expansion, recurse. */
			തിരികെ(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    ഘടന glob_lim *limitp)
{
	ഘടന dirent *dp;
	DIR *dirp;
	പൂർണ്ണസംഖ്യ err;
	അക്ഷരം buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	ഘടന dirent *(*readdirfunc)(ശൂന്യം *);

	എങ്കിൽ (pathend > pathend_last)
		തിരികെ (1);
	*pathend = EOS;
	errno = 0;

	എങ്കിൽ ((dirp = g_opendir(pathbuf, pglob)) == ശൂന്യ) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		എങ്കിൽ (pglob->gl_errfunc) {
			എങ്കിൽ (g_Ctoc(pathbuf, buf, വലുപ്പം(buf)))
				തിരികെ(GLOB_ABORTED);
			എങ്കിൽ (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				തിരികെ(GLOB_ABORTED);
		}
		തിരികെ(0);
	}

	err = 0;

	/* Search directory for matching names. */
	എങ്കിൽ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	അല്ലെങ്കിൽ
		readdirfunc = (ഘടന dirent *(*)(ശൂന്യം *))readdir;
	ആകുമ്പോൾ ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		എങ്കിൽ ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			നിർത്തുക;
		}

		/* Initial DOT must be matched literally. */
		എങ്കിൽ (dp->d_name[0] == DOT && *pattern != DOT)
			തുടരുക;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		ആകുമ്പോൾ (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		എങ്കിൽ (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			നിർത്തുക;
		}

		എങ്കിൽ (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			തുടരുക;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		എങ്കിൽ (err)
			നിർത്തുക;
	}

	എങ്കിൽ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	അല്ലെങ്കിൽ
		closedir(dirp);
	തിരികെ(err);
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
globextend(സ്ഥിരം Char *path, glob_t *pglob, ഘടന glob_lim *limitp,
    ഘടന stat *sb)
{
	അക്ഷരം **pathv;
	size_t i, newn, len;
	അക്ഷരം *copy = ശൂന്യ;
	സ്ഥിരം Char *p;
	ഘടന stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	എങ്കിൽ (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / വലുപ്പം(*pathv) <= newn ||
	    SIZE_MAX / വലുപ്പം(*statv) <= newn) {
 nospace:
		വേണ്ടി (i = pglob->gl_offs; i < newn - 2; i++) {
			എങ്കിൽ (pglob->gl_pathv && pglob->gl_pathv[i])
				സ്വതന്ത്രം(pglob->gl_pathv[i]);
			എങ്കിൽ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				സ്വതന്ത്രം(pglob->gl_statv[i]);
		}
		സ്വതന്ത്രം(pglob->gl_pathv);
		pglob->gl_pathv = ശൂന്യ;
		സ്വതന്ത്രം(pglob->gl_statv);
		pglob->gl_statv = ശൂന്യ;
		തിരികെ(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, വലുപ്പം(*pathv));
	എങ്കിൽ (pathv == ശൂന്യ)
		പോകുക nospace;
	എങ്കിൽ (pglob->gl_pathv == ശൂന്യ && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		വേണ്ടി (i = pglob->gl_offs; i > 0; i--)
			*--pathv = ശൂന്യ;
	}
	pglob->gl_pathv = pathv;

	എങ്കിൽ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, വലുപ്പം(*statv));
		എങ്കിൽ (statv == ശൂന്യ)
			പോകുക nospace;
		എങ്കിൽ (pglob->gl_statv == ശൂന്യ && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			വേണ്ടി (i = pglob->gl_offs; i > 0; i--)
				*--statv = ശൂന്യ;
		}
		pglob->gl_statv = statv;
		എങ്കിൽ (sb == ശൂന്യ)
			statv[pglob->gl_offs + pglob->gl_pathc] = ശൂന്യ;
		അല്ലെങ്കിൽ {
			limitp->glim_malloc += വലുപ്പം(**statv);
			എങ്കിൽ ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				തിരികെ(GLOB_NOSPACE);
			}
			എങ്കിൽ ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(വലുപ്പം(**statv))) == ശൂന്യ)
				പോകുക copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    വലുപ്പം(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = ശൂന്യ;
	}

	വേണ്ടി (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	എങ്കിൽ ((copy = malloc(len)) != ശൂന്യ) {
		എങ്കിൽ (g_Ctoc(path, copy, len)) {
			സ്വതന്ത്രം(copy);
			തിരികെ(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = ശൂന്യ;

	എങ്കിൽ ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * വലുപ്പം(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		തിരികെ(GLOB_NOSPACE);
	}
 copy_error:
	തിരികെ(copy == ശൂന്യ ? GLOB_NOSPACE : 0);
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
match(Char *name, Char *pat, Char *patend)
{
	പൂർണ്ണസംഖ്യ ok, negate_range;
	Char c, k;
	Char *nextp = ശൂന്യ;
	Char *nextn = ശൂന്യ;

loop:
	ആകുമ്പോൾ (pat < patend) {
		c = *pat++;
		തിരഞ്ഞെടുപ്പ് (c & M_MASK) {
		അവസ്ഥ M_ALL:
			ആകുമ്പോൾ (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			എങ്കിൽ (pat == patend)
				തിരികെ(1);
			എങ്കിൽ (*name == EOS)
				തിരികെ(0);
			nextn = name + 1;
			nextp = pat - 1;
			നിർത്തുക;
		അവസ്ഥ M_ONE:
			എങ്കിൽ (*name++ == EOS)
				പോകുക fail;
			നിർത്തുക;
		അവസ്ഥ M_SET:
			ok = 0;
			എങ്കിൽ ((k = *name++) == EOS)
				പോകുക fail;
			എങ്കിൽ ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			ആകുമ്പോൾ (((c = *pat++) & M_MASK) != M_END) {
				എങ്കിൽ ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					എങ്കിൽ (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				എങ്കിൽ ((*pat & M_MASK) == M_RNG) {
					എങ്കിൽ (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} അല്ലെങ്കിൽ എങ്കിൽ (c == k)
					ok = 1;
			}
			എങ്കിൽ (ok == negate_range)
				പോകുക fail;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			എങ്കിൽ (*name++ != c)
				പോകുക fail;
			നിർത്തുക;
		}
	}
	എങ്കിൽ (*name == EOS)
		തിരികെ(1);

fail:
	എങ്കിൽ (nextn) {
		pat = nextp;
		name = nextn;
		പോകുക loop;
	}
	തിരികെ(0);
}

/* Free allocated data belonging to a glob_t structure. */
ശൂന്യം
globfree(glob_t *pglob)
{
	size_t i;
	അക്ഷരം **pp;

	എങ്കിൽ (pglob->gl_pathv != ശൂന്യ) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		വേണ്ടി (i = pglob->gl_pathc; i--; ++pp)
			സ്വതന്ത്രം(*pp);
		സ്വതന്ത്രം(pglob->gl_pathv);
		pglob->gl_pathv = ശൂന്യ;
	}
	എങ്കിൽ (pglob->gl_statv != ശൂന്യ) {
		വേണ്ടി (i = 0; i < pglob->gl_pathc; i++) {
			സ്വതന്ത്രം(pglob->gl_statv[i]);
		}
		സ്വതന്ത്രം(pglob->gl_statv);
		pglob->gl_statv = ശൂന്യ;
	}
}

സ്ഥിതം DIR *
g_opendir(Char *str, glob_t *pglob)
{
	അക്ഷരം buf[PATH_MAX];

	എങ്കിൽ (!*str)
		strlcpy(buf, ".", വലുപ്പം buf);
	അല്ലെങ്കിൽ {
		എങ്കിൽ (g_Ctoc(str, buf, വലുപ്പം(buf)))
			തിരികെ(ശൂന്യ);
	}

	എങ്കിൽ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		തിരികെ((*pglob->gl_opendir)(buf));

	തിരികെ(opendir(buf));
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
g_lstat(Char *fn, ഘടന stat *sb, glob_t *pglob)
{
	അക്ഷരം buf[PATH_MAX];

	എങ്കിൽ (g_Ctoc(fn, buf, വലുപ്പം(buf)))
		തിരികെ(-1);
	എങ്കിൽ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		തിരികെ((*pglob->gl_lstat)(buf, sb));
	തിരികെ(lstat(buf, sb));
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
g_stat(Char *fn, ഘടന stat *sb, glob_t *pglob)
{
	അക്ഷരം buf[PATH_MAX];

	എങ്കിൽ (g_Ctoc(fn, buf, വലുപ്പം(buf)))
		തിരികെ(-1);
	എങ്കിൽ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		തിരികെ((*pglob->gl_stat)(buf, sb));
	തിരികെ(stat(buf, sb));
}

സ്ഥിതം Char *
g_strchr(സ്ഥിരം Char *str, പൂർണ്ണസംഖ്യ ch)
{
	ചെയ്യുക {
		എങ്കിൽ (*str == ch)
			തിരികെ ((Char *)str);
	} ആകുമ്പോൾ (*str++);
	തിരികെ (ശൂന്യ);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
g_Ctoc(സ്ഥിരം Char *str, അക്ഷരം *buf, size_t len)
{

	ആകുമ്പോൾ (len--) {
		എങ്കിൽ ((*buf++ = *str++) == EOS)
			തിരികെ (0);
	}
	തിരികെ (1);
}

#ifdef DEBUG
സ്ഥിതം ശൂന്യം
qprintf(സ്ഥിരം അക്ഷരം *str, Char *s)
{
	Char *p;

	(ശൂന്യം)printf("%s:\n", str);
	വേണ്ടി (p = s; *p; p++)
		(ശൂന്യം)printf("%c", CHAR(*p));
	(ശൂന്യം)printf("\n");
	വേണ്ടി (p = s; *p; p++)
		(ശൂന്യം)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(ശൂന്യം)printf("\n");
	വേണ്ടി (p = s; *p; p++)
		(ശൂന്യം)printf("%c", ismeta(*p) ? '_' : ' ');
	(ശൂന്യം)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
