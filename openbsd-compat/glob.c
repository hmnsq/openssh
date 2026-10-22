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

#यदि !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
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

#अन्यथा

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
	माप_प्रकार	glim_malloc;
	माप_प्रकार	glim_stat;
	माप_प्रकार	glim_readdir;
};

संरचना glob_path_stat {
	वर्ण		*gps_path;
	संरचना stat	*gps_stat;
};

स्थिर पूर्णाङ्क	 compare(अचर शून्य *, अचर शून्य *);
स्थिर पूर्णाङ्क	 compare_gps(अचर शून्य *, अचर शून्य *);
स्थिर पूर्णाङ्क	 g_Ctoc(अचर Char *, वर्ण *, माप_प्रकार);
स्थिर पूर्णाङ्क	 g_lstat(Char *, संरचना stat *, glob_t *);
स्थिर सूची	*g_opendir(Char *, glob_t *);
स्थिर Char	*g_strchr(अचर Char *, पूर्णाङ्क);
स्थिर पूर्णाङ्क	 g_strncmp(अचर Char *, अचर वर्ण *, माप_प्रकार);
स्थिर पूर्णाङ्क	 g_stat(Char *, संरचना stat *, glob_t *);
स्थिर पूर्णाङ्क	 glob0(अचर Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णाङ्क	 glob1(Char *, Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णाङ्क	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, संरचना glob_lim *);
स्थिर पूर्णाङ्क	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णाङ्क	 globextend(अचर Char *, glob_t *, संरचना glob_lim *,
		    संरचना stat *);
स्थिर अचर Char *
		 globtilde(अचर Char *, Char *, माप_प्रकार, glob_t *);
स्थिर पूर्णाङ्क	 globexp1(अचर Char *, glob_t *, संरचना glob_lim *);
स्थिर पूर्णाङ्क	 globexp2(अचर Char *, अचर Char *, glob_t *,
		    संरचना glob_lim *);
स्थिर पूर्णाङ्क	 match(Char *, Char *, Char *);
#ifdef DEBUG
स्थिर शून्य	 qprintf(अचर वर्ण *, Char *);
#endif

पूर्णाङ्क
glob(अचर वर्ण *pattern, पूर्णाङ्क flags, पूर्णाङ्क (*errfunc)(अचर वर्ण *, पूर्णाङ्क),
    glob_t *pglob)
{
	अचर u_char *patnext;
	पूर्णाङ्क c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	संरचना glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	यदि (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = रिक्त;
		pglob->gl_statv = रिक्त;
		यदि (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	यदि (strnlen(pattern, PATH_MAX) == PATH_MAX)
		फर्काऊ(GLOB_NOMATCH);

	यदि (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		फर्काऊ GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	यदि (flags & GLOB_NOESCAPE)
		जबसम्म (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	अन्यथा {
		/* Protect the quoted characters. */
		जबसम्म (bufnext < bufend && (c = *patnext++) != EOS)
			यदि (c == QUOTE) {
				यदि ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} अन्यथा
				*bufnext++ = c;
	}
	*bufnext = EOS;

	यदि (flags & GLOB_BRACE)
		फर्काऊ globexp1(patbuf, pglob, &limit);
	अन्यथा
		फर्काऊ glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
स्थिर पूर्णाङ्क
globexp1(अचर Char *pattern, glob_t *pglob, संरचना glob_lim *limitp)
{
	अचर Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	यदि (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		फर्काऊ glob0(pattern, pglob, limitp);

	यदि ((ptr = (अचर Char *) g_strchr(ptr, LBRACE)) != रिक्त)
		फर्काऊ globexp2(ptr, pattern, pglob, limitp);

	फर्काऊ glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
स्थिर पूर्णाङ्क
globexp2(अचर Char *ptr, अचर Char *pattern, glob_t *pglob,
    संरचना glob_lim *limitp)
{
	पूर्णाङ्क     i, rv;
	Char   *lm, *ls;
	अचर Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	लागि (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	लागि (i = 0, pe = ++ptr; *pe; pe++)
		यदि (*pe == LBRACKET) {
			/* Ignore everything between [] */
			लागि (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			यदि (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} अन्यथा यदि (*pe == LBRACE)
			i++;
		अन्यथा यदि (*pe == RBRACE) {
			यदि (i == 0)
				रोक;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	यदि (i != 0 || *pe == EOS)
		फर्काऊ glob0(patbuf, pglob, limitp);

	लागि (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		विकल्प (*pm) {
		पक्ष LBRACKET:
			/* Ignore everything between [] */
			लागि (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			यदि (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			रोक;

		पक्ष LBRACE:
			i++;
			रोक;

		पक्ष RBRACE:
			यदि (i) {
				i--;
				रोक;
			}
			/* FALLTHROUGH */
		पक्ष COMMA:
			यदि (i && *pm == COMMA)
				रोक;
			अन्यथा {
				/* Append the current string */
				लागि (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				लागि (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#ifdef DEBUG
				qprintf("globexp2:", patbuf);
#endif
				rv = globexp1(patbuf, pglob, limitp);
				यदि (rv && rv != GLOB_NOMATCH)
					फर्काऊ rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			रोक;

		स्वभाव:
			रोक;
		}
	}
	फर्काऊ 0;
}



/*
 * expand tilde from the passwd file.
 */
स्थिर अचर Char *
globtilde(अचर Char *pattern, Char *patbuf, माप_प्रकार patbuf_len, glob_t *pglob)
{
	संरचना passwd *pwd;
	वर्ण *h;
	अचर Char *p;
	Char *b, *eb;

	यदि (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		फर्काऊ pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	लागि (p = pattern + 1, h = (वर्ण *) patbuf;
	    h < (वर्ण *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#यदि 0
	यदि (h == (वर्ण *)eb)
		फर्काऊ what;
#endif

	यदि (((वर्ण *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#यदि 0
		यदि (issetugid() != 0 || (h = दो_पर्या("HOME")) == रिक्त) {
#endif
		यदि ((getuid() != geteuid()) || (h = दो_पर्या("HOME")) == रिक्त) {
			यदि ((pwd = getpwuid(getuid())) == रिक्त)
				फर्काऊ pattern;
			अन्यथा
				h = pwd->pw_dir;
		}
	} अन्यथा {
		/*
		 * Expand a ~user
		 */
		यदि ((pwd = getpwnam((वर्ण*) patbuf)) == रिक्त)
			फर्काऊ pattern;
		अन्यथा
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	लागि (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	जबसम्म (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	फर्काऊ patbuf;
}

स्थिर पूर्णाङ्क
g_strncmp(अचर Char *s1, अचर वर्ण *s2, माप_प्रकार n)
{
	पूर्णाङ्क rv = 0;

	जबसम्म (n--) {
		rv = *(Char *)s1 - *(अचर अचिन्हित वर्ण *)s2++;
		यदि (rv)
			रोक;
		यदि (*s1++ == '\0')
			रोक;
	}
	फर्काऊ rv;
}

स्थिर पूर्णाङ्क
g_charclass(अचर Char **patternp, Char **bufnextp)
{
	अचर Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	अचर Char *colon;
	संरचना cclass *cc;
	माप_प्रकार len;

	यदि ((colon = g_strchr(pattern, ':')) == रिक्त || colon[1] != ']')
		फर्काऊ 1;	/* not a character class */

	len = (माप_प्रकार)(colon - pattern);
	लागि (cc = cclasses; cc->name != रिक्त; cc++) {
		यदि (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			रोक;
	}
	यदि (cc->name == रिक्त)
		फर्काऊ -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	फर्काऊ 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
स्थिर पूर्णाङ्क
glob0(अचर Char *pattern, glob_t *pglob, संरचना glob_lim *limitp)
{
	अचर Char *qpatnext;
	पूर्णाङ्क c, err;
	माप_प्रकार oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	जबसम्म ((c = *qpatnext++) != EOS) {
		विकल्प (c) {
		पक्ष LBRACKET:
			c = *qpatnext;
			यदि (c == NOT)
				++qpatnext;
			यदि (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == रिक्त) {
				*bufnext++ = LBRACKET;
				यदि (c == NOT)
					--qpatnext;
				रोक;
			}
			*bufnext++ = M_SET;
			यदि (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			गर {
				यदि (c == LBRACKET && *qpatnext == ':') {
					गर {
						err = g_charclass(&qpatnext,
						    &bufnext);
						यदि (err)
							रोक;
						c = *qpatnext++;
					} जबसम्म (c == LBRACKET && *qpatnext == ':');
					यदि (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						फर्काऊ GLOB_NOMATCH;
					यदि (c == RBRACKET)
						रोक;
				}
				*bufnext++ = CHAR(c);
				यदि (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} जबसम्म ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			रोक;
		पक्ष QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			रोक;
		पक्ष STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			यदि (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			रोक;
		स्वभाव:
			*bufnext++ = CHAR(c);
			रोक;
		}
	}
	*bufnext = EOS;
#ifdef DEBUG
	qprintf("glob0:", patbuf);
#endif

	यदि ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		फर्काऊ(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	यदि (pglob->gl_pathc == oldpathc) {
		यदि ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			फर्काऊ(globextend(pattern, pglob, limitp, रिक्त));
		अन्यथा
			फर्काऊ(GLOB_NOMATCH);
	}
	यदि (!(pglob->gl_flags & GLOB_NOSORT)) {
		यदि ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			संरचना glob_path_stat *path_stat;
			माप_प्रकार i;
			माप_प्रकार n = pglob->gl_pathc - oldpathc;
			माप_प्रकार o = pglob->gl_offs + oldpathc;

			यदि ((path_stat = सुस्मृति(n, परिमाण(*path_stat))) == रिक्त)
				फर्काऊ GLOB_NOSPACE;
			लागि (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			क्विक(path_stat, n, परिमाण(*path_stat), compare_gps);
			लागि (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			मुक्त(path_stat);
		} अन्यथा {
			क्विक(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, परिमाण(वर्ण *),
			    compare);
		}
	}
	फर्काऊ(0);
}

स्थिर पूर्णाङ्क
compare(अचर शून्य *p, अचर शून्य *q)
{
	फर्काऊ(म_भेद(*(वर्ण **)p, *(वर्ण **)q));
}

स्थिर पूर्णाङ्क
compare_gps(अचर शून्य *_p, अचर शून्य *_q)
{
	अचर संरचना glob_path_stat *p = (अचर संरचना glob_path_stat *)_p;
	अचर संरचना glob_path_stat *q = (अचर संरचना glob_path_stat *)_q;

	फर्काऊ(म_भेद(p->gps_path, q->gps_path));
}

स्थिर पूर्णाङ्क
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, संरचना glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	यदि (*pattern == EOS)
		फर्काऊ(0);
	फर्काऊ(glob2(pathbuf, pathbuf+PATH_MAX-1,
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
	लागि (anymeta = 0;;) {
		यदि (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			यदि ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				त्रुटि_सं = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				फर्काऊ(GLOB_NOSPACE);
			}
			यदि (g_lstat(pathbuf, &sb, pglob))
				फर्काऊ(0);

			यदि (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				यदि (pathend+1 > pathend_last)
					फर्काऊ (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			फर्काऊ(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		जबसम्म (*p != EOS && *p != SEP) {
			यदि (ismeta(*p))
				anymeta = 1;
			यदि (q+1 > pathend_last)
				फर्काऊ (1);
			*q++ = *p++;
		}

		यदि (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			जबसम्म (*pattern == SEP) {
				यदि (pathend+1 > pathend_last)
					फर्काऊ (1);
				*pathend++ = *pattern++;
			}
		} अन्यथा
			/* Need expansion, recurse. */
			फर्काऊ(glob3(pathbuf, pathbuf_last, pathend,
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
	सूची *dirp;
	पूर्णाङ्क err;
	वर्ण buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	संरचना dirent *(*readdirfunc)(शून्य *);

	यदि (pathend > pathend_last)
		फर्काऊ (1);
	*pathend = EOS;
	त्रुटि_सं = 0;

	यदि ((dirp = g_opendir(pathbuf, pglob)) == रिक्त) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		यदि (pglob->gl_errfunc) {
			यदि (g_Ctoc(pathbuf, buf, परिमाण(buf)))
				फर्काऊ(GLOB_ABORTED);
			यदि (pglob->gl_errfunc(buf, त्रुटि_सं) ||
			    pglob->gl_flags & GLOB_ERR)
				फर्काऊ(GLOB_ABORTED);
		}
		फर्काऊ(0);
	}

	err = 0;

	/* Search directory for matching names. */
	यदि (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	अन्यथा
		readdirfunc = (संरचना dirent *(*)(शून्य *))सूची_पढ़ो;
	जबसम्म ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		यदि ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			त्रुटि_सं = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			रोक;
		}

		/* Initial DOT must be matched literally. */
		यदि (dp->d_name[0] == DOT && *pattern != DOT)
			जारी;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		जबसम्म (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		यदि (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			रोक;
		}

		यदि (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			जारी;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		यदि (err)
			रोक;
	}

	यदि (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	अन्यथा
		बंद_सूची(dirp);
	फर्काऊ(err);
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
globextend(अचर Char *path, glob_t *pglob, संरचना glob_lim *limitp,
    संरचना stat *sb)
{
	वर्ण **pathv;
	माप_प्रकार i, newn, len;
	वर्ण *copy = रिक्त;
	अचर Char *p;
	संरचना stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	यदि (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / परिमाण(*pathv) <= newn ||
	    SIZE_MAX / परिमाण(*statv) <= newn) {
 nospace:
		लागि (i = pglob->gl_offs; i < newn - 2; i++) {
			यदि (pglob->gl_pathv && pglob->gl_pathv[i])
				मुक्त(pglob->gl_pathv[i]);
			यदि ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				मुक्त(pglob->gl_statv[i]);
		}
		मुक्त(pglob->gl_pathv);
		pglob->gl_pathv = रिक्त;
		मुक्त(pglob->gl_statv);
		pglob->gl_statv = रिक्त;
		फर्काऊ(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, परिमाण(*pathv));
	यदि (pathv == रिक्त)
		गच्छ nospace;
	यदि (pglob->gl_pathv == रिक्त && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		लागि (i = pglob->gl_offs; i > 0; i--)
			*--pathv = रिक्त;
	}
	pglob->gl_pathv = pathv;

	यदि ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, परिमाण(*statv));
		यदि (statv == रिक्त)
			गच्छ nospace;
		यदि (pglob->gl_statv == रिक्त && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			लागि (i = pglob->gl_offs; i > 0; i--)
				*--statv = रिक्त;
		}
		pglob->gl_statv = statv;
		यदि (sb == रिक्त)
			statv[pglob->gl_offs + pglob->gl_pathc] = रिक्त;
		अन्यथा {
			limitp->glim_malloc += परिमाण(**statv);
			यदि ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				त्रुटि_सं = 0;
				फर्काऊ(GLOB_NOSPACE);
			}
			यदि ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    दो_स्मृति(परिमाण(**statv))) == रिक्त)
				गच्छ copy_error;
			स_नकल(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    परिमाण(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = रिक्त;
	}

	लागि (p = path; *p++;)
		;
	len = (माप_प्रकार)(p - path);
	limitp->glim_malloc += len;
	यदि ((copy = दो_स्मृति(len)) != रिक्त) {
		यदि (g_Ctoc(path, copy, len)) {
			मुक्त(copy);
			फर्काऊ(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = रिक्त;

	यदि ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * परिमाण(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		त्रुटि_सं = 0;
		फर्काऊ(GLOB_NOSPACE);
	}
 copy_error:
	फर्काऊ(copy == रिक्त ? GLOB_NOSPACE : 0);
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
	जबसम्म (pat < patend) {
		c = *pat++;
		विकल्प (c & M_MASK) {
		पक्ष M_ALL:
			जबसम्म (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			यदि (pat == patend)
				फर्काऊ(1);
			यदि (*name == EOS)
				फर्काऊ(0);
			nextn = name + 1;
			nextp = pat - 1;
			रोक;
		पक्ष M_ONE:
			यदि (*name++ == EOS)
				गच्छ fail;
			रोक;
		पक्ष M_SET:
			ok = 0;
			यदि ((k = *name++) == EOS)
				गच्छ fail;
			यदि ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			जबसम्म (((c = *pat++) & M_MASK) != M_END) {
				यदि ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					यदि (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				यदि ((*pat & M_MASK) == M_RNG) {
					यदि (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} अन्यथा यदि (c == k)
					ok = 1;
			}
			यदि (ok == negate_range)
				गच्छ fail;
			रोक;
		स्वभाव:
			यदि (*name++ != c)
				गच्छ fail;
			रोक;
		}
	}
	यदि (*name == EOS)
		फर्काऊ(1);

fail:
	यदि (nextn) {
		pat = nextp;
		name = nextn;
		गच्छ loop;
	}
	फर्काऊ(0);
}

/* Free allocated data belonging to a glob_t structure. */
शून्य
globfree(glob_t *pglob)
{
	माप_प्रकार i;
	वर्ण **pp;

	यदि (pglob->gl_pathv != रिक्त) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		लागि (i = pglob->gl_pathc; i--; ++pp)
			मुक्त(*pp);
		मुक्त(pglob->gl_pathv);
		pglob->gl_pathv = रिक्त;
	}
	यदि (pglob->gl_statv != रिक्त) {
		लागि (i = 0; i < pglob->gl_pathc; i++) {
			मुक्त(pglob->gl_statv[i]);
		}
		मुक्त(pglob->gl_statv);
		pglob->gl_statv = रिक्त;
	}
}

स्थिर सूची *
g_opendir(Char *str, glob_t *pglob)
{
	वर्ण buf[PATH_MAX];

	यदि (!*str)
		strlcpy(buf, ".", परिमाण buf);
	अन्यथा {
		यदि (g_Ctoc(str, buf, परिमाण(buf)))
			फर्काऊ(रिक्त);
	}

	यदि (pglob->gl_flags & GLOB_ALTDIRFUNC)
		फर्काऊ((*pglob->gl_opendir)(buf));

	फर्काऊ(सूची_खोलो(buf));
}

स्थिर पूर्णाङ्क
g_lstat(Char *fn, संरचना stat *sb, glob_t *pglob)
{
	वर्ण buf[PATH_MAX];

	यदि (g_Ctoc(fn, buf, परिमाण(buf)))
		फर्काऊ(-1);
	यदि (pglob->gl_flags & GLOB_ALTDIRFUNC)
		फर्काऊ((*pglob->gl_lstat)(buf, sb));
	फर्काऊ(lstat(buf, sb));
}

स्थिर पूर्णाङ्क
g_stat(Char *fn, संरचना stat *sb, glob_t *pglob)
{
	वर्ण buf[PATH_MAX];

	यदि (g_Ctoc(fn, buf, परिमाण(buf)))
		फर्काऊ(-1);
	यदि (pglob->gl_flags & GLOB_ALTDIRFUNC)
		फर्काऊ((*pglob->gl_stat)(buf, sb));
	फर्काऊ(stat(buf, sb));
}

स्थिर Char *
g_strchr(अचर Char *str, पूर्णाङ्क ch)
{
	गर {
		यदि (*str == ch)
			फर्काऊ ((Char *)str);
	} जबसम्म (*str++);
	फर्काऊ (रिक्त);
}

स्थिर पूर्णाङ्क
g_Ctoc(अचर Char *str, वर्ण *buf, माप_प्रकार len)
{

	जबसम्म (len--) {
		यदि ((*buf++ = *str++) == EOS)
			फर्काऊ (0);
	}
	फर्काऊ (1);
}

#ifdef DEBUG
स्थिर शून्य
qprintf(अचर वर्ण *str, Char *s)
{
	Char *p;

	(शून्य)म_लिखो("%s:\n", str);
	लागि (p = s; *p; p++)
		(शून्य)म_लिखो("%c", CHAR(*p));
	(शून्य)म_लिखो("\n");
	लागि (p = s; *p; p++)
		(शून्य)म_लिखो("%c", *p & M_PROTECT ? '"' : ' ');
	(शून्य)म_लिखो("\n");
	लागि (p = s; *p; p++)
		(शून्य)म_लिखो("%c", ismeta(*p) ? '_' : ' ');
	(शून्य)म_लिखो("\n");
}
#endif

#endif /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
