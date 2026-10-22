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

#अन्तर्भाव "includes.h"
#अन्तर्भाव "glob.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>

#अन्तर्भाव <dirent.h>
#अन्तर्भाव <ctype.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#सचे !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#अन्तर्भाव "charclass.h"

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

प्रकारनिर्देश u_short Char;

#अञ्ञथा

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

प्रकारनिर्देश वर्ण Char;

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

संरचना glob_lim {
	size_t	glim_malloc;
	size_t	glim_stat;
	size_t	glim_readdir;
};

संरचना glob_path_stat {
	वर्ण		*gps_path;
	संरचना stat	*gps_stat;
};

स्थिर पूर्णाङ्क	 compare(ध्रुव शून्य *, ध्रुव शून्य *);
स्थिर पूर्णाङ्क	 compare_gps(ध्रुव शून्य *, ध्रुव शून्य *);
स्थिर पूर्णाङ्क	 g_Ctoc(ध्रुव Char *, वर्ण *, size_t);
स्थिर पूर्णाङ्क	 g_lstat(Char *, संरचना stat *, glob_t *);
स्थिर DIR	*g_opendir(Char *, glob_t *);
स्थिर Char	*g_strchr(ध्रुव Char *, पूर्णाङ्क);
स्थिर पूर्णाङ्क	 g_strncmp(ध्रुव Char *, ध्रुव वर्ण *, size_t);
स्थिर पूर्णाङ्क	 g_stat(Char *, संरचना stat *, glob_t *);
स्थिर पूर्णाङ्क	 glob0(ध्रुव Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णाङ्क	 glob1(Char *, Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णाङ्क	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, संरचना glob_lim *);
स्थिर पूर्णाङ्क	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णाङ्क	 globextend(ध्रुव Char *, glob_t *, संरचना glob_lim *,
		    संरचना stat *);
स्थिर ध्रुव Char *
		 globtilde(ध्रुव Char *, Char *, size_t, glob_t *);
स्थिर पूर्णाङ्क	 globexp1(ध्रुव Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णाङ्क	 globexp2(ध्रुव Char *, ध्रुव Char *, glob_t *,
		    संरचना glob_lim *);
स्थिर पूर्णाङ्क	 match(Char *, Char *, Char *);
#ifdef DEBUG
स्थिर शून्य	 qprintf(ध्रुव वर्ण *, Char *);
#endif

पूर्णाङ्क
glob(ध्रुव वर्ण *pattern, पूर्णाङ्क flags, पूर्णाङ्क (*errfunc)(ध्रुव वर्ण *, पूर्णाङ्क),
    glob_t *pglob)
{
	ध्रुव u_char *patnext;
	पूर्णाङ्क c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	संरचना glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	सचे (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = रिक्त;
		pglob->gl_statv = रिक्त;
		सचे (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	सचे (strnlen(pattern, PATH_MAX) == PATH_MAX)
		पटिनिवत्त(GLOB_NOMATCH);

	सचे (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		पटिनिवत्त GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	सचे (flags & GLOB_NOESCAPE)
		याव (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	अञ्ञथा {
		/* Protect the quoted characters. */
		याव (bufnext < bufend && (c = *patnext++) != EOS)
			सचे (c == QUOTE) {
				सचे ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} अञ्ञथा
				*bufnext++ = c;
	}
	*bufnext = EOS;

	सचे (flags & GLOB_BRACE)
		पटिनिवत्त globexp1(patbuf, pglob, &limit);
	अञ्ञथा
		पटिनिवत्त glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
स्थिर पूर्णाङ्क
globexp1(ध्रुव Char *pattern, glob_t *pglob, संरचना glob_lim *limitp)
{
	ध्रुव Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	सचे (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		पटिनिवत्त glob0(pattern, pglob, limitp);

	सचे ((ptr = (ध्रुव Char *) g_strchr(ptr, LBRACE)) != रिक्त)
		पटिनिवत्त globexp2(ptr, pattern, pglob, limitp);

	पटिनिवत्त glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
स्थिर पूर्णाङ्क
globexp2(ध्रुव Char *ptr, ध्रुव Char *pattern, glob_t *pglob,
    संरचना glob_lim *limitp)
{
	पूर्णाङ्क     i, rv;
	Char   *lm, *ls;
	ध्रुव Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	अत्थाय (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	अत्थाय (i = 0, pe = ++ptr; *pe; pe++)
		सचे (*pe == LBRACKET) {
			/* Ignore everything between [] */
			अत्थाय (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			सचे (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} अञ्ञथा सचे (*pe == LBRACE)
			i++;
		अञ्ञथा सचे (*pe == RBRACE) {
			सचे (i == 0)
				भङ्ग;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	सचे (i != 0 || *pe == EOS)
		पटिनिवत्त glob0(patbuf, pglob, limitp);

	अत्थाय (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		विकल्प (*pm) {
		पक्ष LBRACKET:
			/* Ignore everything between [] */
			अत्थाय (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			सचे (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			भङ्ग;

		पक्ष LBRACE:
			i++;
			भङ्ग;

		पक्ष RBRACE:
			सचे (i) {
				i--;
				भङ्ग;
			}
			/* FALLTHROUGH */
		पक्ष COMMA:
			सचे (i && *pm == COMMA)
				भङ्ग;
			अञ्ञथा {
				/* Append the current string */
				अत्थाय (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				अत्थाय (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				सचे (rv && rv != GLOB_NOMATCH)
					पटिनिवत्त rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			भङ्ग;

		स्वभाव:
			भङ्ग;
		}
	}
	पटिनिवत्त 0;
}



/*
 * expand tilde from the passwd file.
 */
स्थिर ध्रुव Char *
globtilde(ध्रुव Char *pattern, Char *patbuf, size_t patbuf_len, glob_t *pglob)
{
	संरचना passwd *pwd;
	वर्ण *h;
	ध्रुव Char *p;
	Char *b, *eb;

	सचे (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		पटिनिवत्त pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	अत्थाय (p = pattern + 1, h = (वर्ण *) patbuf;
	    h < (वर्ण *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#सचे 0
	सचे (h == (वर्ण *)eb)
		पटिनिवत्त what;
#endif

	सचे (((वर्ण *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#सचे 0
		सचे (issetugid() != 0 || (h = getenv("HOME")) == रिक्त) {
#endif
		सचे ((getuid() != geteuid()) || (h = getenv("HOME")) == रिक्त) {
			सचे ((pwd = getpwuid(getuid())) == रिक्त)
				पटिनिवत्त pattern;
			अञ्ञथा
				h = pwd->pw_dir;
		}
	} अञ्ञथा {
		/*
		 * Expand a ~user
		 */
		सचे ((pwd = getpwnam((वर्ण*) patbuf)) == रिक्त)
			पटिनिवत्त pattern;
		अञ्ञथा
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	अत्थाय (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	याव (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	पटिनिवत्त patbuf;
}

स्थिर पूर्णाङ्क
g_strncmp(ध्रुव Char *s1, ध्रुव वर्ण *s2, size_t n)
{
	पूर्णाङ्क rv = 0;

	याव (n--) {
		rv = *(Char *)s1 - *(ध्रुव unsigned वर्ण *)s2++;
		सचे (rv)
			भङ्ग;
		सचे (*s1++ == '\0')
			भङ्ग;
	}
	पटिनिवत्त rv;
}

स्थिर पूर्णाङ्क
g_charclass(ध्रुव Char **patternp, Char **bufnextp)
{
	ध्रुव Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	ध्रुव Char *colon;
	संरचना cclass *cc;
	size_t len;

	सचे ((colon = g_strchr(pattern, ':')) == रिक्त || colon[1] != ']')
		पटिनिवत्त 1;	/* not a character class */

	len = (size_t)(colon - pattern);
	अत्थाय (cc = cclasses; cc->name != रिक्त; cc++) {
		सचे (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			भङ्ग;
	}
	सचे (cc->name == रिक्त)
		पटिनिवत्त -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	पटिनिवत्त 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
स्थिर पूर्णाङ्क
glob0(ध्रुव Char *pattern, glob_t *pglob, संरचना glob_lim *limitp)
{
	ध्रुव Char *qpatnext;
	पूर्णाङ्क c, err;
	size_t oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	याव ((c = *qpatnext++) != EOS) {
		विकल्प (c) {
		पक्ष LBRACKET:
			c = *qpatnext;
			सचे (c == NOT)
				++qpatnext;
			सचे (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == रिक्त) {
				*bufnext++ = LBRACKET;
				सचे (c == NOT)
					--qpatnext;
				भङ्ग;
			}
			*bufnext++ = M_SET;
			सचे (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			करोहि {
				सचे (c == LBRACKET && *qpatnext == ':') {
					करोहि {
						err = g_charclass(&qpatnext,
						    &bufnext);
						सचे (err)
							भङ्ग;
						c = *qpatnext++;
					} याव (c == LBRACKET && *qpatnext == ':');
					सचे (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						पटिनिवत्त GLOB_NOMATCH;
					सचे (c == RBRACKET)
						भङ्ग;
				}
				*bufnext++ = CHAR(c);
				सचे (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} याव ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			भङ्ग;
		पक्ष QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			भङ्ग;
		पक्ष STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			सचे (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			भङ्ग;
		स्वभाव:
			*bufnext++ = CHAR(c);
			भङ्ग;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	सचे ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		पटिनिवत्त(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	सचे (pglob->gl_pathc == oldpathc) {
		सचे ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			पटिनिवत्त(globextend(pattern, pglob, limitp, रिक्त));
		अञ्ञथा
			पटिनिवत्त(GLOB_NOMATCH);
	}
	सचे (!(pglob->gl_flags & GLOB_NOSORT)) {
		सचे ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			संरचना glob_path_stat *path_stat;
			size_t i;
			size_t n = pglob->gl_pathc - oldpathc;
			size_t o = pglob->gl_offs + oldpathc;

			सचे ((path_stat = calloc(n, परिमाण(*path_stat))) == रिक्त)
				पटिनिवत्त GLOB_NOSPACE;
			अत्थाय (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			qsort(path_stat, n, परिमाण(*path_stat), compare_gps);
			अत्थाय (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			मुक्त(path_stat);
		} अञ्ञथा {
			qsort(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, परिमाण(वर्ण *),
			    compare);
		}
	}
	पटिनिवत्त(0);
}

स्थिर पूर्णाङ्क
compare(ध्रुव शून्य *p, ध्रुव शून्य *q)
{
	पटिनिवत्त(strcmp(*(वर्ण **)p, *(वर्ण **)q));
}

स्थिर पूर्णाङ्क
compare_gps(ध्रुव शून्य *_p, ध्रुव शून्य *_q)
{
	ध्रुव संरचना glob_path_stat *p = (ध्रुव संरचना glob_path_stat *)_p;
	ध्रुव संरचना glob_path_stat *q = (ध्रुव संरचना glob_path_stat *)_q;

	पटिनिवत्त(strcmp(p->gps_path, q->gps_path));
}

स्थिर पूर्णाङ्क
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, संरचना glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	सचे (*pattern == EOS)
		पटिनिवत्त(0);
	पटिनिवत्त(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
स्थिर पूर्णाङ्क
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, संरचना glob_lim *limitp)
{
	संरचना stat sb;
	Char *p, *q;
	पूर्णाङ्क anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	अत्थाय (anymeta = 0;;) {
		सचे (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			सचे ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				errno = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				पटिनिवत्त(GLOB_NOSPACE);
			}
			सचे (g_lstat(pathbuf, &sb, pglob))
				पटिनिवत्त(0);

			सचे (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				सचे (pathend+1 > pathend_last)
					पटिनिवत्त (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			पटिनिवत्त(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		याव (*p != EOS && *p != SEP) {
			सचे (ismeta(*p))
				anymeta = 1;
			सचे (q+1 > pathend_last)
				पटिनिवत्त (1);
			*q++ = *p++;
		}

		सचे (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			याव (*pattern == SEP) {
				सचे (pathend+1 > pathend_last)
					पटिनिवत्त (1);
				*pathend++ = *pattern++;
			}
		} अञ्ञथा
			/* Need expansion, recurse. */
			पटिनिवत्त(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

स्थिर पूर्णाङ्क
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    संरचना glob_lim *limitp)
{
	संरचना dirent *dp;
	DIR *dirp;
	पूर्णाङ्क err;
	वर्ण buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	संरचना dirent *(*readdirfunc)(शून्य *);

	सचे (pathend > pathend_last)
		पटिनिवत्त (1);
	*pathend = EOS;
	errno = 0;

	सचे ((dirp = g_opendir(pathbuf, pglob)) == रिक्त) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		सचे (pglob->gl_errfunc) {
			सचे (g_Ctoc(pathbuf, buf, परिमाण(buf)))
				पटिनिवत्त(GLOB_ABORTED);
			सचे (pglob->gl_errfunc(buf, errno) ||
			    pglob->gl_flags & GLOB_ERR)
				पटिनिवत्त(GLOB_ABORTED);
		}
		पटिनिवत्त(0);
	}

	err = 0;

	/* Search directory for matching names. */
	सचे (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	अञ्ञथा
		readdirfunc = (संरचना dirent *(*)(शून्य *))readdir;
	याव ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		सचे ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			errno = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			भङ्ग;
		}

		/* Initial DOT must be matched literally. */
		सचे (dp->d_name[0] == DOT && *pattern != DOT)
			अनुवर्त;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		याव (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		सचे (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			भङ्ग;
		}

		सचे (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			अनुवर्त;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		सचे (err)
			भङ्ग;
	}

	सचे (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	अञ्ञथा
		closedir(dirp);
	पटिनिवत्त(err);
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
स्थिर पूर्णाङ्क
globextend(ध्रुव Char *path, glob_t *pglob, संरचना glob_lim *limitp,
    संरचना stat *sb)
{
	वर्ण **pathv;
	size_t i, newn, len;
	वर्ण *copy = रिक्त;
	ध्रुव Char *p;
	संरचना stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	सचे (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / परिमाण(*pathv) <= newn ||
	    SIZE_MAX / परिमाण(*statv) <= newn) {
 nospace:
		अत्थाय (i = pglob->gl_offs; i < newn - 2; i++) {
			सचे (pglob->gl_pathv && pglob->gl_pathv[i])
				मुक्त(pglob->gl_pathv[i]);
			सचे ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				मुक्त(pglob->gl_statv[i]);
		}
		मुक्त(pglob->gl_pathv);
		pglob->gl_pathv = रिक्त;
		मुक्त(pglob->gl_statv);
		pglob->gl_statv = रिक्त;
		पटिनिवत्त(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, परिमाण(*pathv));
	सचे (pathv == रिक्त)
		गच्छ nospace;
	सचे (pglob->gl_pathv == रिक्त && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		अत्थाय (i = pglob->gl_offs; i > 0; i--)
			*--pathv = रिक्त;
	}
	pglob->gl_pathv = pathv;

	सचे ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, परिमाण(*statv));
		सचे (statv == रिक्त)
			गच्छ nospace;
		सचे (pglob->gl_statv == रिक्त && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			अत्थाय (i = pglob->gl_offs; i > 0; i--)
				*--statv = रिक्त;
		}
		pglob->gl_statv = statv;
		सचे (sb == रिक्त)
			statv[pglob->gl_offs + pglob->gl_pathc] = रिक्त;
		अञ्ञथा {
			limitp->glim_malloc += परिमाण(**statv);
			सचे ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				errno = 0;
				पटिनिवत्त(GLOB_NOSPACE);
			}
			सचे ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    malloc(परिमाण(**statv))) == रिक्त)
				गच्छ copy_error;
			memcpy(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    परिमाण(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = रिक्त;
	}

	अत्थाय (p = path; *p++;)
		;
	len = (size_t)(p - path);
	limitp->glim_malloc += len;
	सचे ((copy = malloc(len)) != रिक्त) {
		सचे (g_Ctoc(path, copy, len)) {
			मुक्त(copy);
			पटिनिवत्त(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = रिक्त;

	सचे ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * परिमाण(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		errno = 0;
		पटिनिवत्त(GLOB_NOSPACE);
	}
 copy_error:
	पटिनिवत्त(copy == रिक्त ? GLOB_NOSPACE : 0);
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
स्थिर पूर्णाङ्क
match(Char *name, Char *pat, Char *patend)
{
	पूर्णाङ्क ok, negate_range;
	Char c, k;
	Char *nextp = रिक्त;
	Char *nextn = रिक्त;

loop:
	याव (pat < patend) {
		c = *pat++;
		विकल्प (c & M_MASK) {
		पक्ष M_ALL:
			याव (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			सचे (pat == patend)
				पटिनिवत्त(1);
			सचे (*name == EOS)
				पटिनिवत्त(0);
			nextn = name + 1;
			nextp = pat - 1;
			भङ्ग;
		पक्ष M_ONE:
			सचे (*name++ == EOS)
				गच्छ fail;
			भङ्ग;
		पक्ष M_SET:
			ok = 0;
			सचे ((k = *name++) == EOS)
				गच्छ fail;
			सचे ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			याव (((c = *pat++) & M_MASK) != M_END) {
				सचे ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					सचे (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				सचे ((*pat & M_MASK) == M_RNG) {
					सचे (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} अञ्ञथा सचे (c == k)
					ok = 1;
			}
			सचे (ok == negate_range)
				गच्छ fail;
			भङ्ग;
		स्वभाव:
			सचे (*name++ != c)
				गच्छ fail;
			भङ्ग;
		}
	}
	सचे (*name == EOS)
		पटिनिवत्त(1);

fail:
	सचे (nextn) {
		pat = nextp;
		name = nextn;
		गच्छ loop;
	}
	पटिनिवत्त(0);
}

/* Free allocated data belonging to a glob_t structure. */
शून्य
globfree(glob_t *pglob)
{
	size_t i;
	वर्ण **pp;

	सचे (pglob->gl_pathv != रिक्त) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		अत्थाय (i = pglob->gl_pathc; i--; ++pp)
			मुक्त(*pp);
		मुक्त(pglob->gl_pathv);
		pglob->gl_pathv = रिक्त;
	}
	सचे (pglob->gl_statv != रिक्त) {
		अत्थाय (i = 0; i < pglob->gl_pathc; i++) {
			मुक्त(pglob->gl_statv[i]);
		}
		मुक्त(pglob->gl_statv);
		pglob->gl_statv = रिक्त;
	}
}

स्थिर DIR *
g_opendir(Char *str, glob_t *pglob)
{
	वर्ण buf[PATH_MAX];

	सचे (!*str)
		strlcpy(buf, ".", परिमाण buf);
	अञ्ञथा {
		सचे (g_Ctoc(str, buf, परिमाण(buf)))
			पटिनिवत्त(रिक्त);
	}

	सचे (pglob->gl_flags & GLOB_ALTDIRFUNC)
		पटिनिवत्त((*pglob->gl_opendir)(buf));

	पटिनिवत्त(opendir(buf));
}

स्थिर पूर्णाङ्क
g_lstat(Char *fn, संरचना stat *sb, glob_t *pglob)
{
	वर्ण buf[PATH_MAX];

	सचे (g_Ctoc(fn, buf, परिमाण(buf)))
		पटिनिवत्त(-1);
	सचे (pglob->gl_flags & GLOB_ALTDIRFUNC)
		पटिनिवत्त((*pglob->gl_lstat)(buf, sb));
	पटिनिवत्त(lstat(buf, sb));
}

स्थिर पूर्णाङ्क
g_stat(Char *fn, संरचना stat *sb, glob_t *pglob)
{
	वर्ण buf[PATH_MAX];

	सचे (g_Ctoc(fn, buf, परिमाण(buf)))
		पटिनिवत्त(-1);
	सचे (pglob->gl_flags & GLOB_ALTDIRFUNC)
		पटिनिवत्त((*pglob->gl_stat)(buf, sb));
	पटिनिवत्त(stat(buf, sb));
}

स्थिर Char *
g_strchr(ध्रुव Char *str, पूर्णाङ्क ch)
{
	करोहि {
		सचे (*str == ch)
			पटिनिवत्त ((Char *)str);
	} याव (*str++);
	पटिनिवत्त (रिक्त);
}

स्थिर पूर्णाङ्क
g_Ctoc(ध्रुव Char *str, वर्ण *buf, size_t len)
{

	याव (len--) {
		सचे ((*buf++ = *str++) == EOS)
			पटिनिवत्त (0);
	}
	पटिनिवत्त (1);
}

#ifdef DEBUG
स्थिर शून्य
qprintf(ध्रुव वर्ण *str, Char *s)
{
	Char *p;

	(शून्य)printf("%s:\n", str);
	अत्थाय (p = s; *p; p++)
		(शून्य)printf("%c", CHAR(*p));
	(शून्य)printf("\n");
	अत्थाय (p = s; *p; p++)
		(शून्य)printf("%c", *p & M_PROTECT ? '"' : ' ');
	(शून्य)printf("\n");
	अत्थाय (p = s; *p; p++)
		(शून्य)printf("%c", ismeta(*p) ? '_' : ' ');
	(शून्य)printf("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
