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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "glob.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <dirent.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#ਅਨ੍ਤਰ੍ਭਾਵ "charclass.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ TILDE
# undef TILDE
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	DOLLAR		'$'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	DOT		'.'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	EOS		'\0'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	LBRACKET	'['
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	NOT		'!'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	QUESTION	'?'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	QUOTE		'\\'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	RANGE		'-'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	RBRACKET	']'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SEP		'/'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	ਤਾਰਾ		'*'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	TILDE		'~'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	UNDERSCORE	'_'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	LBRACE		'{'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	RBRACE		'}'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SLASH		'/'
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	COMMA		','

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ DEBUG

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_QUOTE		0x8000
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_PROTECT	0x4000
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_ਨਕਾਬ		0xffff
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_ASCII		0x00ff

ਕਿਸਮਪਰਿਭਾਸ਼ਾ u_short Char;

#ਨਹੀਂਤਾਂ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_QUOTE		0x80
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_PROTECT	0x40
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_ਨਕਾਬ		0xff
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_ASCII		0x7f

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਅੱਖਰ Char;

#ਜੇ_ਅੰਤ


#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CHAR(c)		((Char)((c)&M_ASCII))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	META(c)		((Char)((c)|M_QUOTE))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_ALL		META('*')
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_ਸਿਰਾ		META(']')
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_NOT		META('!')
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_ONE		META('?')
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_RNG		META('-')
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_ਸੈੱਟ		META('[')
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	M_CLASS		META(':')
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	ismeta(c)	(((c)&M_QUOTE) != 0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	GLOB_ਹੱਦਬੰਦੀ_MALLOC	65536
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	GLOB_ਹੱਦਬੰਦੀ_STAT		2048
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	GLOB_ਹੱਦਬੰਦੀ_READDIR	16384

ਬਣਤਰ glob_lim {
	ਮਾਪ_t	glim_malloc;
	ਮਾਪ_t	glim_stat;
	ਮਾਪ_t	glim_readdir;
};

ਬਣਤਰ glob_ਰਸਤਾ_stat {
	ਅੱਖਰ		*gps_ਰਸਤਾ;
	ਬਣਤਰ stat	*gps_stat;
};

ਸਥਿਰ ਪੂਰਨ	 compare(ਅਚਲ ਖਾਲੀ *, ਅਚਲ ਖਾਲੀ *);
ਸਥਿਰ ਪੂਰਨ	 compare_gps(ਅਚਲ ਖਾਲੀ *, ਅਚਲ ਖਾਲੀ *);
ਸਥਿਰ ਪੂਰਨ	 g_Ctoc(ਅਚਲ Char *, ਅੱਖਰ *, ਮਾਪ_t);
ਸਥਿਰ ਪੂਰਨ	 g_lstat(Char *, ਬਣਤਰ stat *, glob_t *);
ਸਥਿਰ DIR	*g_opendir(Char *, glob_t *);
ਸਥਿਰ Char	*g_strchr(ਅਚਲ Char *, ਪੂਰਨ);
ਸਥਿਰ ਪੂਰਨ	 g_strncmp(ਅਚਲ Char *, ਅਚਲ ਅੱਖਰ *, ਮਾਪ_t);
ਸਥਿਰ ਪੂਰਨ	 g_stat(Char *, ਬਣਤਰ stat *, glob_t *);
ਸਥਿਰ ਪੂਰਨ	 glob0(ਅਚਲ Char *, glob_t *, ਬਣਤਰ glob_lim *);
ਸਥਿਰ ਪੂਰਨ	 glob1(Char *, Char *, glob_t *, ਬਣਤਰ glob_lim *);
ਸਥਿਰ ਪੂਰਨ	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, ਬਣਤਰ glob_lim *);
ਸਥਿਰ ਪੂਰਨ	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, ਬਣਤਰ glob_lim *);
ਸਥਿਰ ਪੂਰਨ	 globextend(ਅਚਲ Char *, glob_t *, ਬਣਤਰ glob_lim *,
		    ਬਣਤਰ stat *);
ਸਥਿਰ ਅਚਲ Char *
		 globtilde(ਅਚਲ Char *, Char *, ਮਾਪ_t, glob_t *);
ਸਥਿਰ ਪੂਰਨ	 globexp1(ਅਚਲ Char *, glob_t *, ਬਣਤਰ glob_lim *);
ਸਥਿਰ ਪੂਰਨ	 globexp2(ਅਚਲ Char *, ਅਚਲ Char *, glob_t *,
		    ਬਣਤਰ glob_lim *);
ਸਥਿਰ ਪੂਰਨ	 ਮੇਲ(Char *, Char *, Char *);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG
ਸਥਿਰ ਖਾਲੀ	 qprintf(ਅਚਲ ਅੱਖਰ *, Char *);
#ਜੇ_ਅੰਤ

ਪੂਰਨ
glob(ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ, ਪੂਰਨ flags, ਪੂਰਨ (*errfunc)(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ),
    glob_t *pglob)
{
	ਅਚਲ u_char *patnext;
	ਪੂਰਨ c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	ਬਣਤਰ glob_lim ਹੱਦਬੰਦੀ = { 0, 0, 0 };

	patnext = (u_char *) ਨਮੂਨਾ;
	ਜੇ (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = ਨਿਰਾ;
		pglob->gl_statv = ਨਿਰਾ;
		ਜੇ (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	ਜੇ (strnlen(ਨਮੂਨਾ, PATH_MAX) == PATH_MAX)
		ਵਾਪਸ(GLOB_NOMATCH);

	ਜੇ (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		ਵਾਪਸ GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	ਜੇ (flags & GLOB_NOESCAPE)
		ਜਦੋਂ (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	ਨਹੀਂਤਾਂ {
		/* Protect the quoted characters. */
		ਜਦੋਂ (bufnext < bufend && (c = *patnext++) != EOS)
			ਜੇ (c == QUOTE) {
				ਜੇ ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} ਨਹੀਂਤਾਂ
				*bufnext++ = c;
	}
	*bufnext = EOS;

	ਜੇ (flags & GLOB_BRACE)
		ਵਾਪਸ globexp1(patbuf, pglob, &ਹੱਦਬੰਦੀ);
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ glob0(patbuf, pglob, &ਹੱਦਬੰਦੀ);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
ਸਥਿਰ ਪੂਰਨ
globexp1(ਅਚਲ Char *ਨਮੂਨਾ, glob_t *pglob, ਬਣਤਰ glob_lim *limitp)
{
	ਅਚਲ Char* ptr = ਨਮੂਨਾ;

	/* Protect a single {}, for find(1), like csh */
	ਜੇ (ਨਮੂਨਾ[0] == LBRACE && ਨਮੂਨਾ[1] == RBRACE && ਨਮੂਨਾ[2] == EOS)
		ਵਾਪਸ glob0(ਨਮੂਨਾ, pglob, limitp);

	ਜੇ ((ptr = (ਅਚਲ Char *) g_strchr(ptr, LBRACE)) != ਨਿਰਾ)
		ਵਾਪਸ globexp2(ptr, ਨਮੂਨਾ, pglob, limitp);

	ਵਾਪਸ glob0(ਨਮੂਨਾ, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
ਸਥਿਰ ਪੂਰਨ
globexp2(ਅਚਲ Char *ptr, ਅਚਲ Char *ਨਮੂਨਾ, glob_t *pglob,
    ਬਣਤਰ glob_lim *limitp)
{
	ਪੂਰਨ     i, rv;
	Char   *lm, *ls;
	ਅਚਲ Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	ਲਈ (lm = patbuf, pm = ਨਮੂਨਾ; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	ਲਈ (i = 0, pe = ++ptr; *pe; pe++)
		ਜੇ (*pe == LBRACKET) {
			/* Ignore everything between [] */
			ਲਈ (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			ਜੇ (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (*pe == LBRACE)
			i++;
		ਨਹੀਂਤਾਂ ਜੇ (*pe == RBRACE) {
			ਜੇ (i == 0)
				ਰੋਕੋ;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	ਜੇ (i != 0 || *pe == EOS)
		ਵਾਪਸ glob0(patbuf, pglob, limitp);

	ਲਈ (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		ਚੋਣ (*pm) {
		ਹਾਲਤ LBRACKET:
			/* Ignore everything between [] */
			ਲਈ (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			ਜੇ (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			ਰੋਕੋ;

		ਹਾਲਤ LBRACE:
			i++;
			ਰੋਕੋ;

		ਹਾਲਤ RBRACE:
			ਜੇ (i) {
				i--;
				ਰੋਕੋ;
			}
			/* FALLTHROUGH */
		ਹਾਲਤ COMMA:
			ਜੇ (i && *pm == COMMA)
				ਰੋਕੋ;
			ਨਹੀਂਤਾਂ {
				/* Append the current string */
				ਲਈ (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				ਲਈ (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG
				qprintf("globexp2:", patbuf);
#ਜੇ_ਅੰਤ
				rv = globexp1(patbuf, pglob, limitp);
				ਜੇ (rv && rv != GLOB_NOMATCH)
					ਵਾਪਸ rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			ਰੋਕੋ;

		ਮੂਲ:
			ਰੋਕੋ;
		}
	}
	ਵਾਪਸ 0;
}



/*
 * expand tilde from the passwd file.
 */
ਸਥਿਰ ਅਚਲ Char *
globtilde(ਅਚਲ Char *ਨਮੂਨਾ, Char *patbuf, ਮਾਪ_t patbuf_len, glob_t *pglob)
{
	ਬਣਤਰ passwd *pwd;
	ਅੱਖਰ *h;
	ਅਚਲ Char *p;
	Char *b, *eb;

	ਜੇ (*ਨਮੂਨਾ != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		ਵਾਪਸ ਨਮੂਨਾ;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	ਲਈ (p = ਨਮੂਨਾ + 1, h = (ਅੱਖਰ *) patbuf;
	    h < (ਅੱਖਰ *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#ਜੇ 0
	ਜੇ (h == (ਅੱਖਰ *)eb)
		ਵਾਪਸ what;
#ਜੇ_ਅੰਤ

	ਜੇ (((ਅੱਖਰ *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#ਜੇ 0
		ਜੇ (issetugid() != 0 || (h = getenv("HOME")) == ਨਿਰਾ) {
#ਜੇ_ਅੰਤ
		ਜੇ ((getuid() != geteuid()) || (h = getenv("HOME")) == ਨਿਰਾ) {
			ਜੇ ((pwd = getpwuid(getuid())) == ਨਿਰਾ)
				ਵਾਪਸ ਨਮੂਨਾ;
			ਨਹੀਂਤਾਂ
				h = pwd->pw_dir;
		}
	} ਨਹੀਂਤਾਂ {
		/*
		 * Expand a ~user
		 */
		ਜੇ ((pwd = getpwnam((ਅੱਖਰ*) patbuf)) == ਨਿਰਾ)
			ਵਾਪਸ ਨਮੂਨਾ;
		ਨਹੀਂਤਾਂ
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	ਲਈ (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	ਜਦੋਂ (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	ਵਾਪਸ patbuf;
}

ਸਥਿਰ ਪੂਰਨ
g_strncmp(ਅਚਲ Char *s1, ਅਚਲ ਅੱਖਰ *s2, ਮਾਪ_t n)
{
	ਪੂਰਨ rv = 0;

	ਜਦੋਂ (n--) {
		rv = *(Char *)s1 - *(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *)s2++;
		ਜੇ (rv)
			ਰੋਕੋ;
		ਜੇ (*s1++ == '\0')
			ਰੋਕੋ;
	}
	ਵਾਪਸ rv;
}

ਸਥਿਰ ਪੂਰਨ
g_charclass(ਅਚਲ Char **patternp, Char **bufnextp)
{
	ਅਚਲ Char *ਨਮੂਨਾ = *patternp + 1;
	Char *bufnext = *bufnextp;
	ਅਚਲ Char *colon;
	ਬਣਤਰ cclass *cc;
	ਮਾਪ_t len;

	ਜੇ ((colon = g_strchr(ਨਮੂਨਾ, ':')) == ਨਿਰਾ || colon[1] != ']')
		ਵਾਪਸ 1;	/* not a character class */

	len = (ਮਾਪ_t)(colon - ਨਮੂਨਾ);
	ਲਈ (cc = cclasses; cc->name != ਨਿਰਾ; cc++) {
		ਜੇ (!g_strncmp(ਨਮੂਨਾ, cc->name, len) && cc->name[len] == '\0')
			ਰੋਕੋ;
	}
	ਜੇ (cc->name == ਨਿਰਾ)
		ਵਾਪਸ -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	ਵਾਪਸ 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
ਸਥਿਰ ਪੂਰਨ
glob0(ਅਚਲ Char *ਨਮੂਨਾ, glob_t *pglob, ਬਣਤਰ glob_lim *limitp)
{
	ਅਚਲ Char *qpatnext;
	ਪੂਰਨ c, err;
	ਮਾਪ_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(ਨਮੂਨਾ, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	ਜਦੋਂ ((c = *qpatnext++) != EOS) {
		ਚੋਣ (c) {
		ਹਾਲਤ LBRACKET:
			c = *qpatnext;
			ਜੇ (c == NOT)
				++qpatnext;
			ਜੇ (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == ਨਿਰਾ) {
				*bufnext++ = LBRACKET;
				ਜੇ (c == NOT)
					--qpatnext;
				ਰੋਕੋ;
			}
			*bufnext++ = M_ਸੈੱਟ;
			ਜੇ (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			ਕਰੋ {
				ਜੇ (c == LBRACKET && *qpatnext == ':') {
					ਕਰੋ {
						err = g_charclass(&qpatnext,
						    &bufnext);
						ਜੇ (err)
							ਰੋਕੋ;
						c = *qpatnext++;
					} ਜਦੋਂ (c == LBRACKET && *qpatnext == ':');
					ਜੇ (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						ਵਾਪਸ GLOB_NOMATCH;
					ਜੇ (c == RBRACKET)
						ਰੋਕੋ;
				}
				*bufnext++ = CHAR(c);
				ਜੇ (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} ਜਦੋਂ ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ਸਿਰਾ;
			ਰੋਕੋ;
		ਹਾਲਤ QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			ਰੋਕੋ;
		ਹਾਲਤ ਤਾਰਾ:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			ਜੇ (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			ਰੋਕੋ;
		ਮੂਲ:
			*bufnext++ = CHAR(c);
			ਰੋਕੋ;
		}
	}
	*bufnext = EOS;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG
	qprintf("glob0:", patbuf);
#ਜੇ_ਅੰਤ

	ਜੇ ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		ਵਾਪਸ(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	ਜੇ (pglob->gl_pathc == oldpathc) {
		ਜੇ ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			ਵਾਪਸ(globextend(ਨਮੂਨਾ, pglob, limitp, ਨਿਰਾ));
		ਨਹੀਂਤਾਂ
			ਵਾਪਸ(GLOB_NOMATCH);
	}
	ਜੇ (!(pglob->gl_flags & GLOB_NOSORT)) {
		ਜੇ ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			ਬਣਤਰ glob_ਰਸਤਾ_stat *ਰਸਤਾ_stat;
			ਮਾਪ_t i;
			ਮਾਪ_t n = pglob->gl_pathc - oldpathc;
			ਮਾਪ_t o = pglob->gl_offs + oldpathc;

			ਜੇ ((ਰਸਤਾ_stat = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(n, ਆਕਾਰ(*ਰਸਤਾ_stat))) == ਨਿਰਾ)
				ਵਾਪਸ GLOB_NOSPACE;
			ਲਈ (i = 0; i < n; i++) {
				ਰਸਤਾ_stat[i].gps_ਰਸਤਾ = pglob->gl_pathv[o + i];
				ਰਸਤਾ_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(ਰਸਤਾ_stat, n, ਆਕਾਰ(*ਰਸਤਾ_stat), compare_gps);
			ਲਈ (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = ਰਸਤਾ_stat[i].gps_ਰਸਤਾ;
				pglob->gl_statv[o + i] = ਰਸਤਾ_stat[i].gps_stat;
			}
			ਮੁਕਤ(ਰਸਤਾ_stat);
		} ਨਹੀਂਤਾਂ {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, ਆਕਾਰ(ਅੱਖਰ *),
			    compare);
		}
	}
	ਵਾਪਸ(0);
}

ਸਥਿਰ ਪੂਰਨ
compare(ਅਚਲ ਖਾਲੀ *p, ਅਚਲ ਖਾਲੀ *q)
{
	ਵਾਪਸ(strcmp(*(ਅੱਖਰ **)p, *(ਅੱਖਰ **)q));
}

ਸਥਿਰ ਪੂਰਨ
compare_gps(ਅਚਲ ਖਾਲੀ *_p, ਅਚਲ ਖਾਲੀ *_q)
{
	ਅਚਲ ਬਣਤਰ glob_ਰਸਤਾ_stat *p = (ਅਚਲ ਬਣਤਰ glob_ਰਸਤਾ_stat *)_p;
	ਅਚਲ ਬਣਤਰ glob_ਰਸਤਾ_stat *q = (ਅਚਲ ਬਣਤਰ glob_ਰਸਤਾ_stat *)_q;

	ਵਾਪਸ(strcmp(p->gps_ਰਸਤਾ, q->gps_ਰਸਤਾ));
}

ਸਥਿਰ ਪੂਰਨ
glob1(Char *ਨਮੂਨਾ, Char *ਨਮੂਨਾ_ਆਖਰੀ, glob_t *pglob, ਬਣਤਰ glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	ਜੇ (*ਨਮੂਨਾ == EOS)
		ਵਾਪਸ(0);
	ਵਾਪਸ(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    ਨਮੂਨਾ, ਨਮੂਨਾ_ਆਖਰੀ, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
ਸਥਿਰ ਪੂਰਨ
glob2(Char *pathbuf, Char *pathbuf_ਆਖਰੀ, Char *pathend, Char *pathend_ਆਖਰੀ,
    Char *ਨਮੂਨਾ, Char *ਨਮੂਨਾ_ਆਖਰੀ, glob_t *pglob, ਬਣਤਰ glob_lim *limitp)
{
	ਬਣਤਰ stat sb;
	Char *p, *q;
	ਪੂਰਨ anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	ਲਈ (anymeta = 0;;) {
		ਜੇ (*ਨਮੂਨਾ == EOS) {		/* End of pattern? */
			*pathend = EOS;

			ਜੇ ((pglob->gl_flags & GLOB_ਹੱਦਬੰਦੀ) &&
			    limitp->glim_stat++ >= GLOB_ਹੱਦਬੰਦੀ_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				ਵਾਪਸ(GLOB_NOSPACE);
			}
			ਜੇ (g_lstat(pathbuf, &sb, pglob))
				ਵਾਪਸ(0);

			ਜੇ (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				ਜੇ (pathend+1 > pathend_ਆਖਰੀ)
					ਵਾਪਸ (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			ਵਾਪਸ(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = ਨਮੂਨਾ;
		ਜਦੋਂ (*p != EOS && *p != SEP) {
			ਜੇ (ismeta(*p))
				anymeta = 1;
			ਜੇ (q+1 > pathend_ਆਖਰੀ)
				ਵਾਪਸ (1);
			*q++ = *p++;
		}

		ਜੇ (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			ਨਮੂਨਾ = p;
			ਜਦੋਂ (*ਨਮੂਨਾ == SEP) {
				ਜੇ (pathend+1 > pathend_ਆਖਰੀ)
					ਵਾਪਸ (1);
				*pathend++ = *ਨਮੂਨਾ++;
			}
		} ਨਹੀਂਤਾਂ
			/* Need expansion, recurse. */
			ਵਾਪਸ(glob3(pathbuf, pathbuf_ਆਖਰੀ, pathend,
			    pathend_ਆਖਰੀ, ਨਮੂਨਾ, p, ਨਮੂਨਾ_ਆਖਰੀ,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

ਸਥਿਰ ਪੂਰਨ
glob3(Char *pathbuf, Char *pathbuf_ਆਖਰੀ, Char *pathend, Char *pathend_ਆਖਰੀ,
    Char *ਨਮੂਨਾ, Char *restpattern, Char *restpattern_ਆਖਰੀ, glob_t *pglob,
    ਬਣਤਰ glob_lim *limitp)
{
	ਬਣਤਰ dirent *dp;
	DIR *dirp;
	ਪੂਰਨ err;
	ਅੱਖਰ buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	ਬਣਤਰ dirent *(*readdirfunc)(ਖਾਲੀ *);

	ਜੇ (pathend > pathend_ਆਖਰੀ)
		ਵਾਪਸ (1);
	*pathend = EOS;
	errno = 0;

	ਜੇ ((dirp = g_opendir(pathbuf, pglob)) == ਨਿਰਾ) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		ਜੇ (pglob->gl_errfunc) {
			ਜੇ (g_Ctoc(pathbuf, buf, ਆਕਾਰ(buf)))
				ਵਾਪਸ(GLOB_ABORTED);
			ਜੇ (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				ਵਾਪਸ(GLOB_ABORTED);
		}
		ਵਾਪਸ(0);
	}

	err = 0;

	/* Search directory for matching names. */
	ਜੇ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	ਨਹੀਂਤਾਂ
		readdirfunc = (ਬਣਤਰ dirent *(*)(ਖਾਲੀ *))readdir;
	ਜਦੋਂ ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		ਜੇ ((pglob->gl_flags & GLOB_ਹੱਦਬੰਦੀ) &&
		    limitp->glim_readdir++ >= GLOB_ਹੱਦਬੰਦੀ_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			ਰੋਕੋ;
		}

		/* Initial DOT must be matched literally. */
		ਜੇ (dp->d_name[0] == DOT && *ਨਮੂਨਾ != DOT)
			ਜਾਰੀ;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		ਜਦੋਂ (dc < pathend_ਆਖਰੀ && (*dc++ = *sc++) != EOS)
			;
		ਜੇ (dc >= pathend_ਆਖਰੀ) {
			*dc = EOS;
			err = 1;
			ਰੋਕੋ;
		}

		ਜੇ (!ਮੇਲ(pathend, ਨਮੂਨਾ, restpattern)) {
			*pathend = EOS;
			ਜਾਰੀ;
		}
		err = glob2(pathbuf, pathbuf_ਆਖਰੀ, --dc, pathend_ਆਖਰੀ,
		    restpattern, restpattern_ਆਖਰੀ, pglob, limitp);
		ਜੇ (err)
			ਰੋਕੋ;
	}

	ਜੇ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	ਨਹੀਂਤਾਂ
		closedir(dirp);
	ਵਾਪਸ(err);
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
ਸਥਿਰ ਪੂਰਨ
globextend(ਅਚਲ Char *ਰਸਤਾ, glob_t *pglob, ਬਣਤਰ glob_lim *limitp,
    ਬਣਤਰ stat *sb)
{
	ਅੱਖਰ **pathv;
	ਮਾਪ_t i, newn, len;
	ਅੱਖਰ *copy = ਨਿਰਾ;
	ਅਚਲ Char *p;
	ਬਣਤਰ stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	ਜੇ (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / ਆਕਾਰ(*pathv) <= newn ||
	    SIZE_MAX / ਆਕਾਰ(*statv) <= newn) {
 nospace:
		ਲਈ (i = pglob->gl_offs; i < newn - 2; i++) {
			ਜੇ (pglob->gl_pathv && pglob->gl_pathv[i])
				ਮੁਕਤ(pglob->gl_pathv[i]);
			ਜੇ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				ਮੁਕਤ(pglob->gl_statv[i]);
		}
		ਮੁਕਤ(pglob->gl_pathv);
		pglob->gl_pathv = ਨਿਰਾ;
		ਮੁਕਤ(pglob->gl_statv);
		pglob->gl_statv = ਨਿਰਾ;
		ਵਾਪਸ(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, ਆਕਾਰ(*pathv));
	ਜੇ (pathv == ਨਿਰਾ)
		ਜਾਓ nospace;
	ਜੇ (pglob->gl_pathv == ਨਿਰਾ && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		ਲਈ (i = pglob->gl_offs; i > 0; i--)
			*--pathv = ਨਿਰਾ;
	}
	pglob->gl_pathv = pathv;

	ਜੇ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, ਆਕਾਰ(*statv));
		ਜੇ (statv == ਨਿਰਾ)
			ਜਾਓ nospace;
		ਜੇ (pglob->gl_statv == ਨਿਰਾ && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			ਲਈ (i = pglob->gl_offs; i > 0; i--)
				*--statv = ਨਿਰਾ;
		}
		pglob->gl_statv = statv;
		ਜੇ (sb == ਨਿਰਾ)
			statv[pglob->gl_offs + pglob->gl_pathc] = ਨਿਰਾ;
		ਨਹੀਂਤਾਂ {
			limitp->glim_malloc += ਆਕਾਰ(**statv);
			ਜੇ ((pglob->gl_flags & GLOB_ਹੱਦਬੰਦੀ) &&
			    limitp->glim_malloc >= GLOB_ਹੱਦਬੰਦੀ_MALLOC) {
				errno = 0;
				ਵਾਪਸ(GLOB_NOSPACE);
			}
			ਜੇ ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਆਕਾਰ(**statv))) == ਨਿਰਾ)
				ਜਾਓ copy_error;
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    ਆਕਾਰ(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = ਨਿਰਾ;
	}

	ਲਈ (p = ਰਸਤਾ; *p++;)
		;
	len = (ਮਾਪ_t)(p - ਰਸਤਾ);
	limitp->glim_malloc += len;
	ਜੇ ((copy = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len)) != ਨਿਰਾ) {
		ਜੇ (g_Ctoc(ਰਸਤਾ, copy, len)) {
			ਮੁਕਤ(copy);
			ਵਾਪਸ(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = ਨਿਰਾ;

	ਜੇ ((pglob->gl_flags & GLOB_ਹੱਦਬੰਦੀ) &&
	    (newn * ਆਕਾਰ(*pathv)) + limitp->glim_malloc >
	    GLOB_ਹੱਦਬੰਦੀ_MALLOC) {
		errno = 0;
		ਵਾਪਸ(GLOB_NOSPACE);
	}
 copy_error:
	ਵਾਪਸ(copy == ਨਿਰਾ ? GLOB_NOSPACE : 0);
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
ਸਥਿਰ ਪੂਰਨ
ਮੇਲ(Char *name, Char *pat, Char *patend)
{
	ਪੂਰਨ ok, negate_range;
	Char c, k;
	Char *nextp = ਨਿਰਾ;
	Char *nextn = ਨਿਰਾ;

loop:
	ਜਦੋਂ (pat < patend) {
		c = *pat++;
		ਚੋਣ (c & M_ਨਕਾਬ) {
		ਹਾਲਤ M_ALL:
			ਜਦੋਂ (pat < patend && (*pat & M_ਨਕਾਬ) == M_ALL)
				pat++;	/* eat consecutive '*' */
			ਜੇ (pat == patend)
				ਵਾਪਸ(1);
			ਜੇ (*name == EOS)
				ਵਾਪਸ(0);
			nextn = name + 1;
			nextp = pat - 1;
			ਰੋਕੋ;
		ਹਾਲਤ M_ONE:
			ਜੇ (*name++ == EOS)
				ਜਾਓ fail;
			ਰੋਕੋ;
		ਹਾਲਤ M_ਸੈੱਟ:
			ok = 0;
			ਜੇ ((k = *name++) == EOS)
				ਜਾਓ fail;
			ਜੇ ((negate_range = ((*pat & M_ਨਕਾਬ) == M_NOT)) != EOS)
				++pat;
			ਜਦੋਂ (((c = *pat++) & M_ਨਕਾਬ) != M_ਸਿਰਾ) {
				ਜੇ ((c & M_ਨਕਾਬ) == M_CLASS) {
					Char idx = *pat & M_ਨਕਾਬ;
					ਜੇ (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				ਜੇ ((*pat & M_ਨਕਾਬ) == M_RNG) {
					ਜੇ (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} ਨਹੀਂਤਾਂ ਜੇ (c == k)
					ok = 1;
			}
			ਜੇ (ok == negate_range)
				ਜਾਓ fail;
			ਰੋਕੋ;
		ਮੂਲ:
			ਜੇ (*name++ != c)
				ਜਾਓ fail;
			ਰੋਕੋ;
		}
	}
	ਜੇ (*name == EOS)
		ਵਾਪਸ(1);

fail:
	ਜੇ (nextn) {
		pat = nextp;
		name = nextn;
		ਜਾਓ loop;
	}
	ਵਾਪਸ(0);
}

/* Free allocated data belonging to a glob_t structure. */
ਖਾਲੀ
globfree(glob_t *pglob)
{
	ਮਾਪ_t i;
	ਅੱਖਰ **pp;

	ਜੇ (pglob->gl_pathv != ਨਿਰਾ) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		ਲਈ (i = pglob->gl_pathc; i--; ++pp)
			ਮੁਕਤ(*pp);
		ਮੁਕਤ(pglob->gl_pathv);
		pglob->gl_pathv = ਨਿਰਾ;
	}
	ਜੇ (pglob->gl_statv != ਨਿਰਾ) {
		ਲਈ (i = 0; i < pglob->gl_pathc; i++) {
			ਮੁਕਤ(pglob->gl_statv[i]);
		}
		ਮੁਕਤ(pglob->gl_statv);
		pglob->gl_statv = ਨਿਰਾ;
	}
}

ਸਥਿਰ DIR *
g_opendir(Char *str, glob_t *pglob)
{
	ਅੱਖਰ buf[PATH_MAX];

	ਜੇ (!*str)
		strlcpy(buf, ".", ਆਕਾਰ buf);
	ਨਹੀਂਤਾਂ {
		ਜੇ (g_Ctoc(str, buf, ਆਕਾਰ(buf)))
			ਵਾਪਸ(ਨਿਰਾ);
	}

	ਜੇ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ਵਾਪਸ((*pglob->gl_opendir)(buf));

	ਵਾਪਸ(opendir(buf));
}

ਸਥਿਰ ਪੂਰਨ
g_lstat(Char *fn, ਬਣਤਰ stat *sb, glob_t *pglob)
{
	ਅੱਖਰ buf[PATH_MAX];

	ਜੇ (g_Ctoc(fn, buf, ਆਕਾਰ(buf)))
		ਵਾਪਸ(-1);
	ਜੇ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ਵਾਪਸ((*pglob->gl_lstat)(buf, sb));
	ਵਾਪਸ(lstat(buf, sb));
}

ਸਥਿਰ ਪੂਰਨ
g_stat(Char *fn, ਬਣਤਰ stat *sb, glob_t *pglob)
{
	ਅੱਖਰ buf[PATH_MAX];

	ਜੇ (g_Ctoc(fn, buf, ਆਕਾਰ(buf)))
		ਵਾਪਸ(-1);
	ਜੇ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ਵਾਪਸ((*pglob->gl_stat)(buf, sb));
	ਵਾਪਸ(stat(buf, sb));
}

ਸਥਿਰ Char *
g_strchr(ਅਚਲ Char *str, ਪੂਰਨ ch)
{
	ਕਰੋ {
		ਜੇ (*str == ch)
			ਵਾਪਸ ((Char *)str);
	} ਜਦੋਂ (*str++);
	ਵਾਪਸ (ਨਿਰਾ);
}

ਸਥਿਰ ਪੂਰਨ
g_Ctoc(ਅਚਲ Char *str, ਅੱਖਰ *buf, ਮਾਪ_t len)
{

	ਜਦੋਂ (len--) {
		ਜੇ ((*buf++ = *str++) == EOS)
			ਵਾਪਸ (0);
	}
	ਵਾਪਸ (1);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG
ਸਥਿਰ ਖਾਲੀ
qprintf(ਅਚਲ ਅੱਖਰ *str, Char *s)
{
	Char *p;

	(ਖਾਲੀ)ਲਿਖੋ("%s:\n", str);
	ਲਈ (p = s; *p; p++)
		(ਖਾਲੀ)ਲਿਖੋ("%c", CHAR(*p));
	(ਖਾਲੀ)ਲਿਖੋ("\n");
	ਲਈ (p = s; *p; p++)
		(ਖਾਲੀ)ਲਿਖੋ("%c", *p & M_PROTECT ? '"' : ' ');
	(ਖਾਲੀ)ਲਿਖੋ("\n");
	ਲਈ (p = s; *p; p++)
		(ਖਾਲੀ)ਲਿਖੋ("%c", ismeta(*p) ? '_' : ' ');
	(ਖਾਲੀ)ਲਿਖੋ("\n");
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
