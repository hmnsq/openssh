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

#जर !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
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

प्रकारव्याख्या u_short Char;

#अन्यथा

#define	M_QUOTE		0x80
#define	M_PROTECT	0x40
#define	M_MASK		0xff
#define	M_ASCII		0x7f

प्रकारव्याख्या अक्षर Char;

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
	माप_प्रकार	glim_malloc;
	माप_प्रकार	glim_stat;
	माप_प्रकार	glim_readdir;
};

संरचना glob_path_stat {
	अक्षर		*gps_path;
	संरचना stat	*gps_stat;
};

स्थिर पूर्णांक	 compare(स्थिरांक शून्य *, स्थिरांक शून्य *);
स्थिर पूर्णांक	 compare_gps(स्थिरांक शून्य *, स्थिरांक शून्य *);
स्थिर पूर्णांक	 g_Ctoc(स्थिरांक Char *, अक्षर *, माप_प्रकार);
स्थिर पूर्णांक	 g_lstat(Char *, संरचना stat *, glob_t *);
स्थिर सूची	*g_opendir(Char *, glob_t *);
स्थिर Char	*g_strchr(स्थिरांक Char *, पूर्णांक);
स्थिर पूर्णांक	 g_strncmp(स्थिरांक Char *, स्थिरांक अक्षर *, माप_प्रकार);
स्थिर पूर्णांक	 g_stat(Char *, संरचना stat *, glob_t *);
स्थिर पूर्णांक	 glob0(स्थिरांक Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णांक	 glob1(Char *, Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णांक	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, संरचना glob_lim *);
स्थिर पूर्णांक	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णांक	 globextend(स्थिरांक Char *, glob_t *, संरचना glob_lim *,
		    संरचना stat *);
स्थिर स्थिरांक Char *
		 globtilde(स्थिरांक Char *, Char *, माप_प्रकार, glob_t *);
स्थिर पूर्णांक	 globexp1(स्थिरांक Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णांक	 globexp2(स्थिरांक Char *, स्थिरांक Char *, glob_t *,
		    संरचना glob_lim *);
स्थिर पूर्णांक	 match(Char *, Char *, Char *);
#ifdef DEBUG
स्थिर शून्य	 qprintf(स्थिरांक अक्षर *, Char *);
#endif

पूर्णांक
glob(स्थिरांक अक्षर *pattern, पूर्णांक flags, पूर्णांक (*errfunc)(स्थिरांक अक्षर *, पूर्णांक),
    glob_t *pglob)
{
	स्थिरांक u_char *patnext;
	पूर्णांक c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	संरचना glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	जर (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = रिक्त;
		pglob->gl_statv = रिक्त;
		जर (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	जर (strnlen(pattern, PATH_MAX) == PATH_MAX)
		परत(GLOB_NOMATCH);

	जर (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		परत GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	जर (flags & GLOB_NOESCAPE)
		पर्यंत (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	अन्यथा {
		/* Protect the quoted characters. */
		पर्यंत (bufnext < bufend && (c = *patnext++) != EOS)
			जर (c == QUOTE) {
				जर ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} अन्यथा
				*bufnext++ = c;
	}
	*bufnext = EOS;

	जर (flags & GLOB_BRACE)
		परत globexp1(patbuf, pglob, &limit);
	अन्यथा
		परत glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
स्थिर पूर्णांक
globexp1(स्थिरांक Char *pattern, glob_t *pglob, संरचना glob_lim *limitp)
{
	स्थिरांक Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	जर (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		परत glob0(pattern, pglob, limitp);

	जर ((ptr = (स्थिरांक Char *) g_strchr(ptr, LBRACE)) != रिक्त)
		परत globexp2(ptr, pattern, pglob, limitp);

	परत glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
स्थिर पूर्णांक
globexp2(स्थिरांक Char *ptr, स्थिरांक Char *pattern, glob_t *pglob,
    संरचना glob_lim *limitp)
{
	पूर्णांक     i, rv;
	Char   *lm, *ls;
	स्थिरांक Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	साठी (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	साठी (i = 0, pe = ++ptr; *pe; pe++)
		जर (*pe == LBRACKET) {
			/* Ignore everything between [] */
			साठी (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			जर (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} अन्यथा जर (*pe == LBRACE)
			i++;
		अन्यथा जर (*pe == RBRACE) {
			जर (i == 0)
				थांबा;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	जर (i != 0 || *pe == EOS)
		परत glob0(patbuf, pglob, limitp);

	साठी (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		निवड (*pm) {
		स्थिती LBRACKET:
			/* Ignore everything between [] */
			साठी (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			जर (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			थांबा;

		स्थिती LBRACE:
			i++;
			थांबा;

		स्थिती RBRACE:
			जर (i) {
				i--;
				थांबा;
			}
			/* FALLTHROUGH */
		स्थिती COMMA:
			जर (i && *pm == COMMA)
				थांबा;
			अन्यथा {
				/* Append the current string */
				साठी (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				साठी (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				जर (rv && rv != GLOB_NOMATCH)
					परत rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			थांबा;

		पूर्वनिर्धारित:
			थांबा;
		}
	}
	परत 0;
}



/*
 * expand tilde from the passwd file.
 */
स्थिर स्थिरांक Char *
globtilde(स्थिरांक Char *pattern, Char *patbuf, माप_प्रकार patbuf_len, glob_t *pglob)
{
	संरचना passwd *pwd;
	अक्षर *h;
	स्थिरांक Char *p;
	Char *b, *eb;

	जर (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		परत pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	साठी (p = pattern + 1, h = (अक्षर *) patbuf;
	    h < (अक्षर *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#जर 0
	जर (h == (अक्षर *)eb)
		परत what;
#endif

	जर (((अक्षर *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#जर 0
		जर (issetugid() != 0 || (h = दो_पर्या("HOME")) == रिक्त) {
#endif
		जर ((getuid() != geteuid()) || (h = दो_पर्या("HOME")) == रिक्त) {
			जर ((pwd = getpwuid(getuid())) == रिक्त)
				परत pattern;
			अन्यथा
				h = pwd->pw_dir;
		}
	} अन्यथा {
		/*
		 * Expand a ~user
		 */
		जर ((pwd = getpwnam((अक्षर*) patbuf)) == रिक्त)
			परत pattern;
		अन्यथा
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	साठी (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	पर्यंत (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	परत patbuf;
}

स्थिर पूर्णांक
g_strncmp(स्थिरांक Char *s1, स्थिरांक अक्षर *s2, माप_प्रकार n)
{
	पूर्णांक rv = 0;

	पर्यंत (n--) {
		rv = *(Char *)s1 - *(स्थिरांक अचिन्हित अक्षर *)s2++;
		जर (rv)
			थांबा;
		जर (*s1++ == '\0')
			थांबा;
	}
	परत rv;
}

स्थिर पूर्णांक
g_charclass(स्थिरांक Char **patternp, Char **bufnextp)
{
	स्थिरांक Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	स्थिरांक Char *colon;
	संरचना cclass *cc;
	माप_प्रकार len;

	जर ((colon = g_strchr(pattern, ':')) == रिक्त || colon[1] != ']')
		परत 1;	/* not a character class */

	len = (माप_प्रकार)(colon - pattern);
	साठी (cc = cclasses; cc->name != रिक्त; cc++) {
		जर (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			थांबा;
	}
	जर (cc->name == रिक्त)
		परत -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	परत 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
स्थिर पूर्णांक
glob0(स्थिरांक Char *pattern, glob_t *pglob, संरचना glob_lim *limitp)
{
	स्थिरांक Char *qpatnext;
	पूर्णांक c, err;
	माप_प्रकार oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	पर्यंत ((c = *qpatnext++) != EOS) {
		निवड (c) {
		स्थिती LBRACKET:
			c = *qpatnext;
			जर (c == NOT)
				++qpatnext;
			जर (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == रिक्त) {
				*bufnext++ = LBRACKET;
				जर (c == NOT)
					--qpatnext;
				थांबा;
			}
			*bufnext++ = M_SET;
			जर (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			करा {
				जर (c == LBRACKET && *qpatnext == ':') {
					करा {
						err = g_charclass(&qpatnext,
						    &bufnext);
						जर (err)
							थांबा;
						c = *qpatnext++;
					} पर्यंत (c == LBRACKET && *qpatnext == ':');
					जर (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						परत GLOB_NOMATCH;
					जर (c == RBRACKET)
						थांबा;
				}
				*bufnext++ = CHAR(c);
				जर (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} पर्यंत ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			थांबा;
		स्थिती QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			थांबा;
		स्थिती STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			जर (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			थांबा;
		पूर्वनिर्धारित:
			*bufnext++ = CHAR(c);
			थांबा;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	जर ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		परत(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	जर (pglob->gl_pathc == oldpathc) {
		जर ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			परत(globextend(pattern, pglob, limitp, रिक्त));
		अन्यथा
			परत(GLOB_NOMATCH);
	}
	जर (!(pglob->gl_flags & GLOB_NOSORT)) {
		जर ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			संरचना glob_path_stat *path_stat;
			माप_प्रकार i;
			माप_प्रकार n = pglob->gl_pathc - oldpathc;
			माप_प्रकार o = pglob->gl_offs + oldpathc;

			जर ((path_stat = सुस्मृति(n, आकार(*path_stat))) == रिक्त)
				परत GLOB_NOSPACE;
			साठी (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			क्विक(path_stat, n, आकार(*path_stat), compare_gps);
			साठी (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			मुक्त(path_stat);
		} अन्यथा {
			क्विक(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, आकार(अक्षर *),
			    compare);
		}
	}
	परत(0);
}

स्थिर पूर्णांक
compare(स्थिरांक शून्य *p, स्थिरांक शून्य *q)
{
	परत(म_भेद(*(अक्षर **)p, *(अक्षर **)q));
}

स्थिर पूर्णांक
compare_gps(स्थिरांक शून्य *_p, स्थिरांक शून्य *_q)
{
	स्थिरांक संरचना glob_path_stat *p = (स्थिरांक संरचना glob_path_stat *)_p;
	स्थिरांक संरचना glob_path_stat *q = (स्थिरांक संरचना glob_path_stat *)_q;

	परत(म_भेद(p->gps_path, q->gps_path));
}

स्थिर पूर्णांक
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, संरचना glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	जर (*pattern == EOS)
		परत(0);
	परत(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
स्थिर पूर्णांक
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, संरचना glob_lim *limitp)
{
	संरचना stat sb;
	Char *p, *q;
	पूर्णांक anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	साठी (anymeta = 0;;) {
		जर (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			जर ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				त्रुटि_सं = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				परत(GLOB_NOSPACE);
			}
			जर (g_lstat(pathbuf, &sb, pglob))
				परत(0);

			जर (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				जर (pathend+1 > pathend_last)
					परत (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			परत(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		पर्यंत (*p != EOS && *p != SEP) {
			जर (ismeta(*p))
				anymeta = 1;
			जर (q+1 > pathend_last)
				परत (1);
			*q++ = *p++;
		}

		जर (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			पर्यंत (*pattern == SEP) {
				जर (pathend+1 > pathend_last)
					परत (1);
				*pathend++ = *pattern++;
			}
		} अन्यथा
			/* Need expansion, recurse. */
			परत(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

स्थिर पूर्णांक
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    संरचना glob_lim *limitp)
{
	संरचना dirent *dp;
	सूची *dirp;
	पूर्णांक err;
	अक्षर buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	संरचना dirent *(*readdirfunc)(शून्य *);

	जर (pathend > pathend_last)
		परत (1);
	*pathend = EOS;
	त्रुटि_सं = 0;

	जर ((dirp = g_opendir(pathbuf, pglob)) == रिक्त) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		जर (pglob->gl_errfunc) {
			जर (g_Ctoc(pathbuf, buf, आकार(buf)))
				परत(GLOB_ABORTED);
			जर (pglob->gl_errfunc(buf, त्रुटि_सं) ||
			    pglob->gl_flags & GLOB_ERR)
				परत(GLOB_ABORTED);
		}
		परत(0);
	}

	err = 0;

	/* Search directory for matching names. */
	जर (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	अन्यथा
		readdirfunc = (संरचना dirent *(*)(शून्य *))सूची_पढ़ो;
	पर्यंत ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		जर ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			त्रुटि_सं = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			थांबा;
		}

		/* Initial DOT must be matched literally. */
		जर (dp->d_name[0] == DOT && *pattern != DOT)
			सुरूठेवा;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		पर्यंत (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		जर (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			थांबा;
		}

		जर (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			सुरूठेवा;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		जर (err)
			थांबा;
	}

	जर (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	अन्यथा
		बंद_सूची(dirp);
	परत(err);
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
स्थिर पूर्णांक
globextend(स्थिरांक Char *path, glob_t *pglob, संरचना glob_lim *limitp,
    संरचना stat *sb)
{
	अक्षर **pathv;
	माप_प्रकार i, newn, len;
	अक्षर *copy = रिक्त;
	स्थिरांक Char *p;
	संरचना stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	जर (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / आकार(*pathv) <= newn ||
	    SIZE_MAX / आकार(*statv) <= newn) {
 nospace:
		साठी (i = pglob->gl_offs; i < newn - 2; i++) {
			जर (pglob->gl_pathv && pglob->gl_pathv[i])
				मुक्त(pglob->gl_pathv[i]);
			जर ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				मुक्त(pglob->gl_statv[i]);
		}
		मुक्त(pglob->gl_pathv);
		pglob->gl_pathv = रिक्त;
		मुक्त(pglob->gl_statv);
		pglob->gl_statv = रिक्त;
		परत(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, आकार(*pathv));
	जर (pathv == रिक्त)
		जा nospace;
	जर (pglob->gl_pathv == रिक्त && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		साठी (i = pglob->gl_offs; i > 0; i--)
			*--pathv = रिक्त;
	}
	pglob->gl_pathv = pathv;

	जर ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, आकार(*statv));
		जर (statv == रिक्त)
			जा nospace;
		जर (pglob->gl_statv == रिक्त && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			साठी (i = pglob->gl_offs; i > 0; i--)
				*--statv = रिक्त;
		}
		pglob->gl_statv = statv;
		जर (sb == रिक्त)
			statv[pglob->gl_offs + pglob->gl_pathc] = रिक्त;
		अन्यथा {
			limitp->glim_malloc += आकार(**statv);
			जर ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				त्रुटि_सं = 0;
				परत(GLOB_NOSPACE);
			}
			जर ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    दो_स्मृति(आकार(**statv))) == रिक्त)
				जा copy_error;
			स_नकल(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    आकार(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = रिक्त;
	}

	साठी (p = path; *p++;)
		;
	len = (माप_प्रकार)(p - path);
	limitp->glim_malloc += len;
	जर ((copy = दो_स्मृति(len)) != रिक्त) {
		जर (g_Ctoc(path, copy, len)) {
			मुक्त(copy);
			परत(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = रिक्त;

	जर ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * आकार(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		त्रुटि_सं = 0;
		परत(GLOB_NOSPACE);
	}
 copy_error:
	परत(copy == रिक्त ? GLOB_NOSPACE : 0);
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
स्थिर पूर्णांक
match(Char *name, Char *pat, Char *patend)
{
	पूर्णांक ok, negate_range;
	Char c, k;
	Char *nextp = रिक्त;
	Char *nextn = रिक्त;

loop:
	पर्यंत (pat < patend) {
		c = *pat++;
		निवड (c & M_MASK) {
		स्थिती M_ALL:
			पर्यंत (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			जर (pat == patend)
				परत(1);
			जर (*name == EOS)
				परत(0);
			nextn = name + 1;
			nextp = pat - 1;
			थांबा;
		स्थिती M_ONE:
			जर (*name++ == EOS)
				जा fail;
			थांबा;
		स्थिती M_SET:
			ok = 0;
			जर ((k = *name++) == EOS)
				जा fail;
			जर ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			पर्यंत (((c = *pat++) & M_MASK) != M_END) {
				जर ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					जर (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				जर ((*pat & M_MASK) == M_RNG) {
					जर (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} अन्यथा जर (c == k)
					ok = 1;
			}
			जर (ok == negate_range)
				जा fail;
			थांबा;
		पूर्वनिर्धारित:
			जर (*name++ != c)
				जा fail;
			थांबा;
		}
	}
	जर (*name == EOS)
		परत(1);

fail:
	जर (nextn) {
		pat = nextp;
		name = nextn;
		जा loop;
	}
	परत(0);
}

/* Free allocated data belonging to a glob_t structure. */
शून्य
globfree(glob_t *pglob)
{
	माप_प्रकार i;
	अक्षर **pp;

	जर (pglob->gl_pathv != रिक्त) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		साठी (i = pglob->gl_pathc; i--; ++pp)
			मुक्त(*pp);
		मुक्त(pglob->gl_pathv);
		pglob->gl_pathv = रिक्त;
	}
	जर (pglob->gl_statv != रिक्त) {
		साठी (i = 0; i < pglob->gl_pathc; i++) {
			मुक्त(pglob->gl_statv[i]);
		}
		मुक्त(pglob->gl_statv);
		pglob->gl_statv = रिक्त;
	}
}

स्थिर सूची *
g_opendir(Char *str, glob_t *pglob)
{
	अक्षर buf[PATH_MAX];

	जर (!*str)
		strlcpy(buf, ".", आकार buf);
	अन्यथा {
		जर (g_Ctoc(str, buf, आकार(buf)))
			परत(रिक्त);
	}

	जर (pglob->gl_flags & GLOB_ALTDIRFUNC)
		परत((*pglob->gl_opendir)(buf));

	परत(सूची_खोलो(buf));
}

स्थिर पूर्णांक
g_lstat(Char *fn, संरचना stat *sb, glob_t *pglob)
{
	अक्षर buf[PATH_MAX];

	जर (g_Ctoc(fn, buf, आकार(buf)))
		परत(-1);
	जर (pglob->gl_flags & GLOB_ALTDIRFUNC)
		परत((*pglob->gl_lstat)(buf, sb));
	परत(lstat(buf, sb));
}

स्थिर पूर्णांक
g_stat(Char *fn, संरचना stat *sb, glob_t *pglob)
{
	अक्षर buf[PATH_MAX];

	जर (g_Ctoc(fn, buf, आकार(buf)))
		परत(-1);
	जर (pglob->gl_flags & GLOB_ALTDIRFUNC)
		परत((*pglob->gl_stat)(buf, sb));
	परत(stat(buf, sb));
}

स्थिर Char *
g_strchr(स्थिरांक Char *str, पूर्णांक ch)
{
	करा {
		जर (*str == ch)
			परत ((Char *)str);
	} पर्यंत (*str++);
	परत (रिक्त);
}

स्थिर पूर्णांक
g_Ctoc(स्थिरांक Char *str, अक्षर *buf, माप_प्रकार len)
{

	पर्यंत (len--) {
		जर ((*buf++ = *str++) == EOS)
			परत (0);
	}
	परत (1);
}

#ifdef DEBUG
स्थिर शून्य
qprintf(स्थिरांक अक्षर *str, Char *s)
{
	Char *p;

	(शून्य)म_लिखो("%s:\n", str);
	साठी (p = s; *p; p++)
		(शून्य)म_लिखो("%c", CHAR(*p));
	(शून्य)म_लिखो("\n");
	साठी (p = s; *p; p++)
		(शून्य)म_लिखो("%c", *p & M_PROTECT ? '"' : ' ');
	(शून्य)म_लिखो("\n");
	साठी (p = s; *p; p++)
		(शून्य)म_लिखो("%c", ismeta(*p) ? '_' : ' ');
	(शून्य)म_लिखो("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
