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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ "glob.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <dirent.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಆದರೆ !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#ಅನ್ತರ್ಭಾವ "charclass.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ TILDE
# undef TILDE
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು	DOLLAR		'$'
#ವ್ಯಾಖ್ಯಾನಿಸು	DOT		'.'
#ವ್ಯಾಖ್ಯಾನಿಸು	EOS		'\0'
#ವ್ಯಾಖ್ಯಾನಿಸು	LBRACKET	'['
#ವ್ಯಾಖ್ಯಾನಿಸು	NOT		'!'
#ವ್ಯಾಖ್ಯಾನಿಸು	QUESTION	'?'
#ವ್ಯಾಖ್ಯಾನಿಸು	QUOTE		'\\'
#ವ್ಯಾಖ್ಯಾನಿಸು	RANGE		'-'
#ವ್ಯಾಖ್ಯಾನಿಸು	RBRACKET	']'
#ವ್ಯಾಖ್ಯಾನಿಸು	SEP		'/'
#ವ್ಯಾಖ್ಯಾನಿಸು	ನಕ್ಷತ್ರ		'*'
#ವ್ಯಾಖ್ಯಾನಿಸು	TILDE		'~'
#ವ್ಯಾಖ್ಯಾನಿಸು	UNDERSCORE	'_'
#ವ್ಯಾಖ್ಯಾನಿಸು	LBRACE		'{'
#ವ್ಯಾಖ್ಯಾನಿಸು	RBRACE		'}'
#ವ್ಯಾಖ್ಯಾನಿಸು	SLASH		'/'
#ವ್ಯಾಖ್ಯಾನಿಸು	COMMA		','

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ DEBUG

#ವ್ಯಾಖ್ಯಾನಿಸು	M_QUOTE		0x8000
#ವ್ಯಾಖ್ಯಾನಿಸು	M_PROTECT	0x4000
#ವ್ಯಾಖ್ಯಾನಿಸು	M_ಮುಖವಾಡ		0xffff
#ವ್ಯಾಖ್ಯಾನಿಸು	M_ASCII		0x00ff

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ u_short Char;

#ಇಲ್ಲದಿದ್ದರೆ

#ವ್ಯಾಖ್ಯಾನಿಸು	M_QUOTE		0x80
#ವ್ಯಾಖ್ಯಾನಿಸು	M_PROTECT	0x40
#ವ್ಯಾಖ್ಯಾನಿಸು	M_ಮುಖವಾಡ		0xff
#ವ್ಯಾಖ್ಯಾನಿಸು	M_ASCII		0x7f

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಅಕ್ಷರ Char;

#ಆದರೆ_ಅಂತ್ಯ


#ವ್ಯಾಖ್ಯಾನಿಸು	CHAR(c)		((Char)((c)&M_ASCII))
#ವ್ಯಾಖ್ಯಾನಿಸು	META(c)		((Char)((c)|M_QUOTE))
#ವ್ಯಾಖ್ಯಾನಿಸು	M_ALL		META('*')
#ವ್ಯಾಖ್ಯಾನಿಸು	M_ಕೊನೆ		META(']')
#ವ್ಯಾಖ್ಯಾನಿಸು	M_NOT		META('!')
#ವ್ಯಾಖ್ಯಾನಿಸು	M_ONE		META('?')
#ವ್ಯಾಖ್ಯಾನಿಸು	M_RNG		META('-')
#ವ್ಯಾಖ್ಯಾನಿಸು	M_ಗಣ		META('[')
#ವ್ಯಾಖ್ಯಾನಿಸು	M_CLASS		META(':')
#ವ್ಯಾಖ್ಯಾನಿಸು	ismeta(c)	(((c)&M_QUOTE) != 0)

#ವ್ಯಾಖ್ಯಾನಿಸು	GLOB_ಎಲ್ಲೆ_MALLOC	65536
#ವ್ಯಾಖ್ಯಾನಿಸು	GLOB_ಎಲ್ಲೆ_STAT		2048
#ವ್ಯಾಖ್ಯಾನಿಸು	GLOB_ಎಲ್ಲೆ_READDIR	16384

ರಚನೆ glob_lim {
	ಗಾತ್ರ_t	glim_malloc;
	ಗಾತ್ರ_t	glim_stat;
	ಗಾತ್ರ_t	glim_readdir;
};

ರಚನೆ glob_ಮಾರ್ಗ_stat {
	ಅಕ್ಷರ		*gps_ಮಾರ್ಗ;
	ರಚನೆ stat	*gps_stat;
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 compare(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 compare_gps(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 g_Ctoc(ಸ್ಥಿರಾಂಕ Char *, ಅಕ್ಷರ *, ಗಾತ್ರ_t);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 g_lstat(Char *, ರಚನೆ stat *, glob_t *);
ಸ್ಥಿರ DIR	*g_opendir(Char *, glob_t *);
ಸ್ಥಿರ Char	*g_strchr(ಸ್ಥಿರಾಂಕ Char *, ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 g_strncmp(ಸ್ಥಿರಾಂಕ Char *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಗಾತ್ರ_t);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 g_stat(Char *, ರಚನೆ stat *, glob_t *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 glob0(ಸ್ಥಿರಾಂಕ Char *, glob_t *, ರಚನೆ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 glob1(Char *, Char *, glob_t *, ರಚನೆ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, ರಚನೆ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, ರಚನೆ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 globextend(ಸ್ಥಿರಾಂಕ Char *, glob_t *, ರಚನೆ glob_lim *,
		    ರಚನೆ stat *);
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ Char *
		 globtilde(ಸ್ಥಿರಾಂಕ Char *, Char *, ಗಾತ್ರ_t, glob_t *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 globexp1(ಸ್ಥಿರಾಂಕ Char *, glob_t *, ರಚನೆ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 globexp2(ಸ್ಥಿರಾಂಕ Char *, ಸ್ಥಿರಾಂಕ Char *, glob_t *,
		    ರಚನೆ glob_lim *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 ಹೊಂದಿಕೆ(Char *, Char *, Char *);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG
ಸ್ಥಿರ ಶೂನ್ಯ	 qprintf(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, Char *);
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
glob(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ, ಪೂರ್ಣಾಂಕ flags, ಪೂರ್ಣಾಂಕ (*errfunc)(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ),
    glob_t *pglob)
{
	ಸ್ಥಿರಾಂಕ u_char *patnext;
	ಪೂರ್ಣಾಂಕ c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	ರಚನೆ glob_lim ಎಲ್ಲೆ = { 0, 0, 0 };

	patnext = (u_char *) ನಮೂನೆ;
	ಆದರೆ (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = ಖಾಲಿ;
		pglob->gl_statv = ಖಾಲಿ;
		ಆದರೆ (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	ಆದರೆ (strnlen(ನಮೂನೆ, PATH_MAX) == PATH_MAX)
		ಹಿಂತಿರುಗಿ(GLOB_NOMATCH);

	ಆದರೆ (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		ಹಿಂತಿರುಗಿ GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	ಆದರೆ (flags & GLOB_NOESCAPE)
		ಆಗ (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	ಇಲ್ಲದಿದ್ದರೆ {
		/* Protect the quoted characters. */
		ಆಗ (bufnext < bufend && (c = *patnext++) != EOS)
			ಆದರೆ (c == QUOTE) {
				ಆದರೆ ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} ಇಲ್ಲದಿದ್ದರೆ
				*bufnext++ = c;
	}
	*bufnext = EOS;

	ಆದರೆ (flags & GLOB_BRACE)
		ಹಿಂತಿರುಗಿ globexp1(patbuf, pglob, &ಎಲ್ಲೆ);
	ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ glob0(patbuf, pglob, &ಎಲ್ಲೆ);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
globexp1(ಸ್ಥಿರಾಂಕ Char *ನಮೂನೆ, glob_t *pglob, ರಚನೆ glob_lim *limitp)
{
	ಸ್ಥಿರಾಂಕ Char* ptr = ನಮೂನೆ;

	/* Protect a single {}, for find(1), like csh */
	ಆದರೆ (ನಮೂನೆ[0] == LBRACE && ನಮೂನೆ[1] == RBRACE && ನಮೂನೆ[2] == EOS)
		ಹಿಂತಿರುಗಿ glob0(ನಮೂನೆ, pglob, limitp);

	ಆದರೆ ((ptr = (ಸ್ಥಿರಾಂಕ Char *) g_strchr(ptr, LBRACE)) != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ globexp2(ptr, ನಮೂನೆ, pglob, limitp);

	ಹಿಂತಿರುಗಿ glob0(ನಮೂನೆ, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
globexp2(ಸ್ಥಿರಾಂಕ Char *ptr, ಸ್ಥಿರಾಂಕ Char *ನಮೂನೆ, glob_t *pglob,
    ರಚನೆ glob_lim *limitp)
{
	ಪೂರ್ಣಾಂಕ     i, rv;
	Char   *lm, *ls;
	ಸ್ಥಿರಾಂಕ Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	ಗಾಗಿ (lm = patbuf, pm = ನಮೂನೆ; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	ಗಾಗಿ (i = 0, pe = ++ptr; *pe; pe++)
		ಆದರೆ (*pe == LBRACKET) {
			/* Ignore everything between [] */
			ಗಾಗಿ (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			ಆದರೆ (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*pe == LBRACE)
			i++;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*pe == RBRACE) {
			ಆದರೆ (i == 0)
				ನಿಲ್ಲಿಸು;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	ಆದರೆ (i != 0 || *pe == EOS)
		ಹಿಂತಿರುಗಿ glob0(patbuf, pglob, limitp);

	ಗಾಗಿ (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		ಆಯ್ಕೆ (*pm) {
		ಸ್ಥಿತಿ LBRACKET:
			/* Ignore everything between [] */
			ಗಾಗಿ (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			ಆದರೆ (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ LBRACE:
			i++;
			ನಿಲ್ಲಿಸು;

		ಸ್ಥಿತಿ RBRACE:
			ಆದರೆ (i) {
				i--;
				ನಿಲ್ಲಿಸು;
			}
			/* FALLTHROUGH */
		ಸ್ಥಿತಿ COMMA:
			ಆದರೆ (i && *pm == COMMA)
				ನಿಲ್ಲಿಸು;
			ಇಲ್ಲದಿದ್ದರೆ {
				/* Append the current string */
				ಗಾಗಿ (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				ಗಾಗಿ (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG
				qprintf("globexp2:", patbuf);
#ಆದರೆ_ಅಂತ್ಯ
				rv = globexp1(patbuf, pglob, limitp);
				ಆದರೆ (rv && rv != GLOB_NOMATCH)
					ಹಿಂತಿರುಗಿ rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			ನಿಲ್ಲಿಸು;

		ಪೂರ್ವನಿಯೋಜಿತ:
			ನಿಲ್ಲಿಸು;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}



/*
 * expand tilde from the passwd file.
 */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ Char *
globtilde(ಸ್ಥಿರಾಂಕ Char *ನಮೂನೆ, Char *patbuf, ಗಾತ್ರ_t patbuf_len, glob_t *pglob)
{
	ರಚನೆ passwd *pwd;
	ಅಕ್ಷರ *h;
	ಸ್ಥಿರಾಂಕ Char *p;
	Char *b, *eb;

	ಆದರೆ (*ನಮೂನೆ != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		ಹಿಂತಿರುಗಿ ನಮೂನೆ;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	ಗಾಗಿ (p = ನಮೂನೆ + 1, h = (ಅಕ್ಷರ *) patbuf;
	    h < (ಅಕ್ಷರ *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#ಆದರೆ 0
	ಆದರೆ (h == (ಅಕ್ಷರ *)eb)
		ಹಿಂತಿರುಗಿ what;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (((ಅಕ್ಷರ *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#ಆದರೆ 0
		ಆದರೆ (issetugid() != 0 || (h = getenv("HOME")) == ಖಾಲಿ) {
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ ((getuid() != geteuid()) || (h = getenv("HOME")) == ಖಾಲಿ) {
			ಆದರೆ ((pwd = getpwuid(getuid())) == ಖಾಲಿ)
				ಹಿಂತಿರುಗಿ ನಮೂನೆ;
			ಇಲ್ಲದಿದ್ದರೆ
				h = pwd->pw_dir;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		/*
		 * Expand a ~user
		 */
		ಆದರೆ ((pwd = getpwnam((ಅಕ್ಷರ*) patbuf)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ ನಮೂನೆ;
		ಇಲ್ಲದಿದ್ದರೆ
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	ಗಾಗಿ (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	ಆಗ (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	ಹಿಂತಿರುಗಿ patbuf;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
g_strncmp(ಸ್ಥಿರಾಂಕ Char *s1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s2, ಗಾತ್ರ_t n)
{
	ಪೂರ್ಣಾಂಕ rv = 0;

	ಆಗ (n--) {
		rv = *(Char *)s1 - *(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *)s2++;
		ಆದರೆ (rv)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (*s1++ == '\0')
			ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ rv;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
g_charclass(ಸ್ಥಿರಾಂಕ Char **patternp, Char **bufnextp)
{
	ಸ್ಥಿರಾಂಕ Char *ನಮೂನೆ = *patternp + 1;
	Char *bufnext = *bufnextp;
	ಸ್ಥಿರಾಂಕ Char *colon;
	ರಚನೆ cclass *cc;
	ಗಾತ್ರ_t len;

	ಆದರೆ ((colon = g_strchr(ನಮೂನೆ, ':')) == ಖಾಲಿ || colon[1] != ']')
		ಹಿಂತಿರುಗಿ 1;	/* not a character class */

	len = (ಗಾತ್ರ_t)(colon - ನಮೂನೆ);
	ಗಾಗಿ (cc = cclasses; cc->name != ಖಾಲಿ; cc++) {
		ಆದರೆ (!g_strncmp(ನಮೂನೆ, cc->name, len) && cc->name[len] == '\0')
			ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (cc->name == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	ಹಿಂತಿರುಗಿ 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
glob0(ಸ್ಥಿರಾಂಕ Char *ನಮೂನೆ, glob_t *pglob, ರಚನೆ glob_lim *limitp)
{
	ಸ್ಥಿರಾಂಕ Char *qpatnext;
	ಪೂರ್ಣಾಂಕ c, err;
	ಗಾತ್ರ_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(ನಮೂನೆ, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	ಆಗ ((c = *qpatnext++) != EOS) {
		ಆಯ್ಕೆ (c) {
		ಸ್ಥಿತಿ LBRACKET:
			c = *qpatnext;
			ಆದರೆ (c == NOT)
				++qpatnext;
			ಆದರೆ (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == ಖಾಲಿ) {
				*bufnext++ = LBRACKET;
				ಆದರೆ (c == NOT)
					--qpatnext;
				ನಿಲ್ಲಿಸು;
			}
			*bufnext++ = M_ಗಣ;
			ಆದರೆ (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			ಮಾಡು {
				ಆದರೆ (c == LBRACKET && *qpatnext == ':') {
					ಮಾಡು {
						err = g_charclass(&qpatnext,
						    &bufnext);
						ಆದರೆ (err)
							ನಿಲ್ಲಿಸು;
						c = *qpatnext++;
					} ಆಗ (c == LBRACKET && *qpatnext == ':');
					ಆದರೆ (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						ಹಿಂತಿರುಗಿ GLOB_NOMATCH;
					ಆದರೆ (c == RBRACKET)
						ನಿಲ್ಲಿಸು;
				}
				*bufnext++ = CHAR(c);
				ಆದರೆ (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} ಆಗ ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ಕೊನೆ;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ನಕ್ಷತ್ರ:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			ಆದರೆ (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			*bufnext++ = CHAR(c);
			ನಿಲ್ಲಿಸು;
		}
	}
	*bufnext = EOS;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG
	qprintf("glob0:", patbuf);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		ಹಿಂತಿರುಗಿ(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	ಆದರೆ (pglob->gl_pathc == oldpathc) {
		ಆದರೆ ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			ಹಿಂತಿರುಗಿ(globextend(ನಮೂನೆ, pglob, limitp, ಖಾಲಿ));
		ಇಲ್ಲದಿದ್ದರೆ
			ಹಿಂತಿರುಗಿ(GLOB_NOMATCH);
	}
	ಆದರೆ (!(pglob->gl_flags & GLOB_NOSORT)) {
		ಆದರೆ ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			ರಚನೆ glob_ಮಾರ್ಗ_stat *ಮಾರ್ಗ_stat;
			ಗಾತ್ರ_t i;
			ಗಾತ್ರ_t n = pglob->gl_pathc - oldpathc;
			ಗಾತ್ರ_t o = pglob->gl_offs + oldpathc;

			ಆದರೆ ((ಮಾರ್ಗ_stat = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(n, ಗಾತ್ರ(*ಮಾರ್ಗ_stat))) == ಖಾಲಿ)
				ಹಿಂತಿರುಗಿ GLOB_NOSPACE;
			ಗಾಗಿ (i = 0; i < n; i++) {
				ಮಾರ್ಗ_stat[i].gps_ಮಾರ್ಗ = pglob->gl_pathv[o + i];
				ಮಾರ್ಗ_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(ಮಾರ್ಗ_stat, n, ಗಾತ್ರ(*ಮಾರ್ಗ_stat), compare_gps);
			ಗಾಗಿ (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = ಮಾರ್ಗ_stat[i].gps_ಮಾರ್ಗ;
				pglob->gl_statv[o + i] = ಮಾರ್ಗ_stat[i].gps_stat;
			}
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ_stat);
		} ಇಲ್ಲದಿದ್ದರೆ {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, ಗಾತ್ರ(ಅಕ್ಷರ *),
			    compare);
		}
	}
	ಹಿಂತಿರುಗಿ(0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
compare(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *p, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *q)
{
	ಹಿಂತಿರುಗಿ(strcmp(*(ಅಕ್ಷರ **)p, *(ಅಕ್ಷರ **)q));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
compare_gps(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *_p, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *_q)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ glob_ಮಾರ್ಗ_stat *p = (ಸ್ಥಿರಾಂಕ ರಚನೆ glob_ಮಾರ್ಗ_stat *)_p;
	ಸ್ಥಿರಾಂಕ ರಚನೆ glob_ಮಾರ್ಗ_stat *q = (ಸ್ಥಿರಾಂಕ ರಚನೆ glob_ಮಾರ್ಗ_stat *)_q;

	ಹಿಂತಿರುಗಿ(strcmp(p->gps_ಮಾರ್ಗ, q->gps_ಮಾರ್ಗ));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
glob1(Char *ನಮೂನೆ, Char *ನಮೂನೆ_ಕೊನೆಯ, glob_t *pglob, ರಚನೆ glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	ಆದರೆ (*ನಮೂನೆ == EOS)
		ಹಿಂತಿರುಗಿ(0);
	ಹಿಂತಿರುಗಿ(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    ನಮೂನೆ, ನಮೂನೆ_ಕೊನೆಯ, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
glob2(Char *pathbuf, Char *pathbuf_ಕೊನೆಯ, Char *pathend, Char *pathend_ಕೊನೆಯ,
    Char *ನಮೂನೆ, Char *ನಮೂನೆ_ಕೊನೆಯ, glob_t *pglob, ರಚನೆ glob_lim *limitp)
{
	ರಚನೆ stat sb;
	Char *p, *q;
	ಪೂರ್ಣಾಂಕ anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	ಗಾಗಿ (anymeta = 0;;) {
		ಆದರೆ (*ನಮೂನೆ == EOS) {		/* End of pattern? */
			*pathend = EOS;

			ಆದರೆ ((pglob->gl_flags & GLOB_ಎಲ್ಲೆ) &&
			    limitp->glim_stat++ >= GLOB_ಎಲ್ಲೆ_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				ಹಿಂತಿರುಗಿ(GLOB_NOSPACE);
			}
			ಆದರೆ (g_lstat(pathbuf, &sb, pglob))
				ಹಿಂತಿರುಗಿ(0);

			ಆದರೆ (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				ಆದರೆ (pathend+1 > pathend_ಕೊನೆಯ)
					ಹಿಂತಿರುಗಿ (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			ಹಿಂತಿರುಗಿ(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = ನಮೂನೆ;
		ಆಗ (*p != EOS && *p != SEP) {
			ಆದರೆ (ismeta(*p))
				anymeta = 1;
			ಆದರೆ (q+1 > pathend_ಕೊನೆಯ)
				ಹಿಂತಿರುಗಿ (1);
			*q++ = *p++;
		}

		ಆದರೆ (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			ನಮೂನೆ = p;
			ಆಗ (*ನಮೂನೆ == SEP) {
				ಆದರೆ (pathend+1 > pathend_ಕೊನೆಯ)
					ಹಿಂತಿರುಗಿ (1);
				*pathend++ = *ನಮೂನೆ++;
			}
		} ಇಲ್ಲದಿದ್ದರೆ
			/* Need expansion, recurse. */
			ಹಿಂತಿರುಗಿ(glob3(pathbuf, pathbuf_ಕೊನೆಯ, pathend,
			    pathend_ಕೊನೆಯ, ನಮೂನೆ, p, ನಮೂನೆ_ಕೊನೆಯ,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
glob3(Char *pathbuf, Char *pathbuf_ಕೊನೆಯ, Char *pathend, Char *pathend_ಕೊನೆಯ,
    Char *ನಮೂನೆ, Char *restpattern, Char *restpattern_ಕೊನೆಯ, glob_t *pglob,
    ರಚನೆ glob_lim *limitp)
{
	ರಚನೆ dirent *dp;
	DIR *dirp;
	ಪೂರ್ಣಾಂಕ err;
	ಅಕ್ಷರ buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	ರಚನೆ dirent *(*readdirfunc)(ಶೂನ್ಯ *);

	ಆದರೆ (pathend > pathend_ಕೊನೆಯ)
		ಹಿಂತಿರುಗಿ (1);
	*pathend = EOS;
	errno = 0;

	ಆದರೆ ((dirp = g_opendir(pathbuf, pglob)) == ಖಾಲಿ) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		ಆದರೆ (pglob->gl_errfunc) {
			ಆದರೆ (g_Ctoc(pathbuf, buf, ಗಾತ್ರ(buf)))
				ಹಿಂತಿರುಗಿ(GLOB_ABORTED);
			ಆದರೆ (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				ಹಿಂತಿರುಗಿ(GLOB_ABORTED);
		}
		ಹಿಂತಿರುಗಿ(0);
	}

	err = 0;

	/* Search directory for matching names. */
	ಆದರೆ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	ಇಲ್ಲದಿದ್ದರೆ
		readdirfunc = (ರಚನೆ dirent *(*)(ಶೂನ್ಯ *))readdir;
	ಆಗ ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		ಆದರೆ ((pglob->gl_flags & GLOB_ಎಲ್ಲೆ) &&
		    limitp->glim_readdir++ >= GLOB_ಎಲ್ಲೆ_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			ನಿಲ್ಲಿಸು;
		}

		/* Initial DOT must be matched literally. */
		ಆದರೆ (dp->d_name[0] == DOT && *ನಮೂನೆ != DOT)
			ಮುಂದುವರಿ;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		ಆಗ (dc < pathend_ಕೊನೆಯ && (*dc++ = *sc++) != EOS)
			;
		ಆದರೆ (dc >= pathend_ಕೊನೆಯ) {
			*dc = EOS;
			err = 1;
			ನಿಲ್ಲಿಸು;
		}

		ಆದರೆ (!ಹೊಂದಿಕೆ(pathend, ನಮೂನೆ, restpattern)) {
			*pathend = EOS;
			ಮುಂದುವರಿ;
		}
		err = glob2(pathbuf, pathbuf_ಕೊನೆಯ, --dc, pathend_ಕೊನೆಯ,
		    restpattern, restpattern_ಕೊನೆಯ, pglob, limitp);
		ಆದರೆ (err)
			ನಿಲ್ಲಿಸು;
	}

	ಆದರೆ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	ಇಲ್ಲದಿದ್ದರೆ
		closedir(dirp);
	ಹಿಂತಿರುಗಿ(err);
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
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
globextend(ಸ್ಥಿರಾಂಕ Char *ಮಾರ್ಗ, glob_t *pglob, ರಚನೆ glob_lim *limitp,
    ರಚನೆ stat *sb)
{
	ಅಕ್ಷರ **pathv;
	ಗಾತ್ರ_t i, newn, len;
	ಅಕ್ಷರ *copy = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ Char *p;
	ರಚನೆ stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	ಆದರೆ (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / ಗಾತ್ರ(*pathv) <= newn ||
	    SIZE_MAX / ಗಾತ್ರ(*statv) <= newn) {
 nospace:
		ಗಾಗಿ (i = pglob->gl_offs; i < newn - 2; i++) {
			ಆದರೆ (pglob->gl_pathv && pglob->gl_pathv[i])
				ಬಿಡುಗಡೆ(pglob->gl_pathv[i]);
			ಆದರೆ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				ಬಿಡುಗಡೆ(pglob->gl_statv[i]);
		}
		ಬಿಡುಗಡೆ(pglob->gl_pathv);
		pglob->gl_pathv = ಖಾಲಿ;
		ಬಿಡುಗಡೆ(pglob->gl_statv);
		pglob->gl_statv = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, ಗಾತ್ರ(*pathv));
	ಆದರೆ (pathv == ಖಾಲಿ)
		ಹೋಗು nospace;
	ಆದರೆ (pglob->gl_pathv == ಖಾಲಿ && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		ಗಾಗಿ (i = pglob->gl_offs; i > 0; i--)
			*--pathv = ಖಾಲಿ;
	}
	pglob->gl_pathv = pathv;

	ಆದರೆ ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, ಗಾತ್ರ(*statv));
		ಆದರೆ (statv == ಖಾಲಿ)
			ಹೋಗು nospace;
		ಆದರೆ (pglob->gl_statv == ಖಾಲಿ && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			ಗಾಗಿ (i = pglob->gl_offs; i > 0; i--)
				*--statv = ಖಾಲಿ;
		}
		pglob->gl_statv = statv;
		ಆದರೆ (sb == ಖಾಲಿ)
			statv[pglob->gl_offs + pglob->gl_pathc] = ಖಾಲಿ;
		ಇಲ್ಲದಿದ್ದರೆ {
			limitp->glim_malloc += ಗಾತ್ರ(**statv);
			ಆದರೆ ((pglob->gl_flags & GLOB_ಎಲ್ಲೆ) &&
			    limitp->glim_malloc >= GLOB_ಎಲ್ಲೆ_MALLOC) {
				errno = 0;
				ಹಿಂತಿರುಗಿ(GLOB_NOSPACE);
			}
			ಆದರೆ ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ(**statv))) == ಖಾಲಿ)
				ಹೋಗು copy_error;
			ಸ್ಮರಣೆ_ನಕಲು(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    ಗಾತ್ರ(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = ಖಾಲಿ;
	}

	ಗಾಗಿ (p = ಮಾರ್ಗ; *p++;)
		;
	len = (ಗಾತ್ರ_t)(p - ಮಾರ್ಗ);
	limitp->glim_malloc += len;
	ಆದರೆ ((copy = ಸ್ಮರಣೆ_ಕೊಡು(len)) != ಖಾಲಿ) {
		ಆದರೆ (g_Ctoc(ಮಾರ್ಗ, copy, len)) {
			ಬಿಡುಗಡೆ(copy);
			ಹಿಂತಿರುಗಿ(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = ಖಾಲಿ;

	ಆದರೆ ((pglob->gl_flags & GLOB_ಎಲ್ಲೆ) &&
	    (newn * ಗಾತ್ರ(*pathv)) + limitp->glim_malloc >
	    GLOB_ಎಲ್ಲೆ_MALLOC) {
		errno = 0;
		ಹಿಂತಿರುಗಿ(GLOB_NOSPACE);
	}
 copy_error:
	ಹಿಂತಿರುಗಿ(copy == ಖಾಲಿ ? GLOB_NOSPACE : 0);
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
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ(Char *name, Char *pat, Char *patend)
{
	ಪೂರ್ಣಾಂಕ ok, negate_range;
	Char c, k;
	Char *nextp = ಖಾಲಿ;
	Char *nextn = ಖಾಲಿ;

loop:
	ಆಗ (pat < patend) {
		c = *pat++;
		ಆಯ್ಕೆ (c & M_ಮುಖವಾಡ) {
		ಸ್ಥಿತಿ M_ALL:
			ಆಗ (pat < patend && (*pat & M_ಮುಖವಾಡ) == M_ALL)
				pat++;	/* eat consecutive '*' */
			ಆದರೆ (pat == patend)
				ಹಿಂತಿರುಗಿ(1);
			ಆದರೆ (*name == EOS)
				ಹಿಂತಿರುಗಿ(0);
			nextn = name + 1;
			nextp = pat - 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ M_ONE:
			ಆದರೆ (*name++ == EOS)
				ಹೋಗು fail;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ M_ಗಣ:
			ok = 0;
			ಆದರೆ ((k = *name++) == EOS)
				ಹೋಗು fail;
			ಆದರೆ ((negate_range = ((*pat & M_ಮುಖವಾಡ) == M_NOT)) != EOS)
				++pat;
			ಆಗ (((c = *pat++) & M_ಮುಖವಾಡ) != M_ಕೊನೆ) {
				ಆದರೆ ((c & M_ಮುಖವಾಡ) == M_CLASS) {
					Char idx = *pat & M_ಮುಖವಾಡ;
					ಆದರೆ (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				ಆದರೆ ((*pat & M_ಮುಖವಾಡ) == M_RNG) {
					ಆದರೆ (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c == k)
					ok = 1;
			}
			ಆದರೆ (ok == negate_range)
				ಹೋಗು fail;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಆದರೆ (*name++ != c)
				ಹೋಗು fail;
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (*name == EOS)
		ಹಿಂತಿರುಗಿ(1);

fail:
	ಆದರೆ (nextn) {
		pat = nextp;
		name = nextn;
		ಹೋಗು loop;
	}
	ಹಿಂತಿರುಗಿ(0);
}

/* Free allocated data belonging to a glob_t structure. */
ಶೂನ್ಯ
globfree(glob_t *pglob)
{
	ಗಾತ್ರ_t i;
	ಅಕ್ಷರ **pp;

	ಆದರೆ (pglob->gl_pathv != ಖಾಲಿ) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		ಗಾಗಿ (i = pglob->gl_pathc; i--; ++pp)
			ಬಿಡುಗಡೆ(*pp);
		ಬಿಡುಗಡೆ(pglob->gl_pathv);
		pglob->gl_pathv = ಖಾಲಿ;
	}
	ಆದರೆ (pglob->gl_statv != ಖಾಲಿ) {
		ಗಾಗಿ (i = 0; i < pglob->gl_pathc; i++) {
			ಬಿಡುಗಡೆ(pglob->gl_statv[i]);
		}
		ಬಿಡುಗಡೆ(pglob->gl_statv);
		pglob->gl_statv = ಖಾಲಿ;
	}
}

ಸ್ಥಿರ DIR *
g_opendir(Char *str, glob_t *pglob)
{
	ಅಕ್ಷರ buf[PATH_MAX];

	ಆದರೆ (!*str)
		strlcpy(buf, ".", ಗಾತ್ರ buf);
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (g_Ctoc(str, buf, ಗಾತ್ರ(buf)))
			ಹಿಂತಿರುಗಿ(ಖಾಲಿ);
	}

	ಆದರೆ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ಹಿಂತಿರುಗಿ((*pglob->gl_opendir)(buf));

	ಹಿಂತಿರುಗಿ(opendir(buf));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
g_lstat(Char *fn, ರಚನೆ stat *sb, glob_t *pglob)
{
	ಅಕ್ಷರ buf[PATH_MAX];

	ಆದರೆ (g_Ctoc(fn, buf, ಗಾತ್ರ(buf)))
		ಹಿಂತಿರುಗಿ(-1);
	ಆದರೆ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ಹಿಂತಿರುಗಿ((*pglob->gl_lstat)(buf, sb));
	ಹಿಂತಿರುಗಿ(lstat(buf, sb));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
g_stat(Char *fn, ರಚನೆ stat *sb, glob_t *pglob)
{
	ಅಕ್ಷರ buf[PATH_MAX];

	ಆದರೆ (g_Ctoc(fn, buf, ಗಾತ್ರ(buf)))
		ಹಿಂತಿರುಗಿ(-1);
	ಆದರೆ (pglob->gl_flags & GLOB_ALTDIRFUNC)
		ಹಿಂತಿರುಗಿ((*pglob->gl_stat)(buf, sb));
	ಹಿಂತಿರುಗಿ(stat(buf, sb));
}

ಸ್ಥಿರ Char *
g_strchr(ಸ್ಥಿರಾಂಕ Char *str, ಪೂರ್ಣಾಂಕ ch)
{
	ಮಾಡು {
		ಆದರೆ (*str == ch)
			ಹಿಂತಿರುಗಿ ((Char *)str);
	} ಆಗ (*str++);
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
g_Ctoc(ಸ್ಥಿರಾಂಕ Char *str, ಅಕ್ಷರ *buf, ಗಾತ್ರ_t len)
{

	ಆಗ (len--) {
		ಆದರೆ ((*buf++ = *str++) == EOS)
			ಹಿಂತಿರುಗಿ (0);
	}
	ಹಿಂತಿರುಗಿ (1);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG
ಸ್ಥಿರ ಶೂನ್ಯ
qprintf(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str, Char *s)
{
	Char *p;

	(ಶೂನ್ಯ)ಬರೆ("%s:\n", str);
	ಗಾಗಿ (p = s; *p; p++)
		(ಶೂನ್ಯ)ಬರೆ("%c", CHAR(*p));
	(ಶೂನ್ಯ)ಬರೆ("\n");
	ಗಾಗಿ (p = s; *p; p++)
		(ಶೂನ್ಯ)ಬರೆ("%c", *p & M_PROTECT ? '"' : ' ');
	(ಶೂನ್ಯ)ಬರೆ("\n");
	ಗಾಗಿ (p = s; *p; p++)
		(ಶೂನ್ಯ)ಬರೆ("%c", ismeta(*p) ? '_' : ' ');
	(ಶೂನ್ಯ)ಬರೆ("\n");
}
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
