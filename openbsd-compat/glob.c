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

#समावेश "includes.h"
#समावेश "glob.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <dirent.h>
#समावेश <ctype.h>
#समावेश <errno.h>
#समावेश <limits.h>
#समावेश <pwd.h>
#समावेश <stdlib.h>
#समावेश <stdint.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) || \
    !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) || \
    !defined(HAVE_DECL_GLOB_NOMATCH) || HAVE_DECL_GLOB_NOMATCH == 0 || \
    defined(BROKEN_GLOB)

#समावेश "charclass.h"

#अगर_घोषित TILDE
# undef TILDE
#पूर्ण_अगर

#घोषणा	DOLLAR		'$'
#घोषणा	DOT		'.'
#घोषणा	EOS		'\0'
#घोषणा	LBRACKET	'['
#घोषणा	NOT		'!'
#घोषणा	QUESTION	'?'
#घोषणा	QUOTE		'\\'
#घोषणा	RANGE		'-'
#घोषणा	RBRACKET	']'
#घोषणा	SEP		'/'
#घोषणा	STAR		'*'
#घोषणा	TILDE		'~'
#घोषणा	UNDERSCORE	'_'
#घोषणा	LBRACE		'{'
#घोषणा	RBRACE		'}'
#घोषणा	SLASH		'/'
#घोषणा	COMMA		','

#अगर_अघोषित DEBUG

#घोषणा	M_QUOTE		0x8000
#घोषणा	M_PROTECT	0x4000
#घोषणा	M_MASK		0xffff
#घोषणा	M_ASCII		0x00ff

प्रकार u_short Char;

#अन्यथा

#घोषणा	M_QUOTE		0x80
#घोषणा	M_PROTECT	0x40
#घोषणा	M_MASK		0xff
#घोषणा	M_ASCII		0x7f

प्रकार अक्षर Char;

#पूर्ण_अगर


#घोषणा	CHAR(c)		((Char)((c)&M_ASCII))
#घोषणा	META(c)		((Char)((c)|M_QUOTE))
#घोषणा	M_ALL		META('*')
#घोषणा	M_END		META(']')
#घोषणा	M_NOT		META('!')
#घोषणा	M_ONE		META('?')
#घोषणा	M_RNG		META('-')
#घोषणा	M_SET		META('[')
#घोषणा	M_CLASS		META(':')
#घोषणा	ismeta(c)	(((c)&M_QUOTE) != 0)

#घोषणा	GLOB_LIMIT_MALLOC	65536
#घोषणा	GLOB_LIMIT_STAT		2048
#घोषणा	GLOB_LIMIT_READDIR	16384

काष्ठा glob_lim {
	माप_प्रकार	glim_malloc;
	माप_प्रकार	glim_stat;
	माप_प्रकार	glim_readdir;
};

काष्ठा glob_path_stat {
	अक्षर		*gps_path;
	काष्ठा stat	*gps_stat;
};

अटल पूर्णांक	 compare(स्थिर व्योम *, स्थिर व्योम *);
अटल पूर्णांक	 compare_gps(स्थिर व्योम *, स्थिर व्योम *);
अटल पूर्णांक	 g_Ctoc(स्थिर Char *, अक्षर *, माप_प्रकार);
अटल पूर्णांक	 g_lstat(Char *, काष्ठा stat *, glob_t *);
अटल सूची	*g_opendir(Char *, glob_t *);
अटल Char	*g_strchr(स्थिर Char *, पूर्णांक);
अटल पूर्णांक	 g_strncmp(स्थिर Char *, स्थिर अक्षर *, माप_प्रकार);
अटल पूर्णांक	 g_stat(Char *, काष्ठा stat *, glob_t *);
अटल पूर्णांक	 glob0(स्थिर Char *, glob_t *, काष्ठा glob_lim *);
अटल पूर्णांक	 glob1(Char *, Char *, glob_t *, काष्ठा glob_lim *);
अटल पूर्णांक	 glob2(Char *, Char *, Char *, Char *, Char *, Char *,
		    glob_t *, काष्ठा glob_lim *);
अटल पूर्णांक	 glob3(Char *, Char *, Char *, Char *, Char *,
		    Char *, Char *, glob_t *, काष्ठा glob_lim *);
अटल पूर्णांक	 globextend(स्थिर Char *, glob_t *, काष्ठा glob_lim *,
		    काष्ठा stat *);
अटल स्थिर Char *
		 globtilde(स्थिर Char *, Char *, माप_प्रकार, glob_t *);
अटल पूर्णांक	 globexp1(स्थिर Char *, glob_t *, काष्ठा glob_lim *);
अटल पूर्णांक	 globexp2(स्थिर Char *, स्थिर Char *, glob_t *,
		    काष्ठा glob_lim *);
अटल पूर्णांक	 match(Char *, Char *, Char *);
#अगर_घोषित DEBUG
अटल व्योम	 qprintf(स्थिर अक्षर *, Char *);
#पूर्ण_अगर

पूर्णांक
glob(स्थिर अक्षर *pattern, पूर्णांक flags, पूर्णांक (*errfunc)(स्थिर अक्षर *, पूर्णांक),
    glob_t *pglob)
{
	स्थिर u_char *patnext;
	पूर्णांक c;
	Char *bufnext, *bufend, patbuf[PATH_MAX];
	काष्ठा glob_lim limit = { 0, 0, 0 };

	patnext = (u_char *) pattern;
	अगर (!(flags & GLOB_APPEND)) {
		pglob->gl_pathc = 0;
		pglob->gl_pathv = शून्य;
		pglob->gl_statv = शून्य;
		अगर (!(flags & GLOB_DOOFFS))
			pglob->gl_offs = 0;
	}
	pglob->gl_flags = flags & ~GLOB_MAGCHAR;
	pglob->gl_errfunc = errfunc;
	pglob->gl_matchc = 0;

	अगर (strnlen(pattern, PATH_MAX) == PATH_MAX)
		वापस(GLOB_NOMATCH);

	अगर (pglob->gl_offs >= SSIZE_MAX || pglob->gl_pathc >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX - pglob->gl_offs - 1)
		वापस GLOB_NOSPACE;

	bufnext = patbuf;
	bufend = bufnext + PATH_MAX - 1;
	अगर (flags & GLOB_NOESCAPE)
		जबतक (bufnext < bufend && (c = *patnext++) != EOS)
			*bufnext++ = c;
	अन्यथा {
		/* Protect the quoted characters. */
		जबतक (bufnext < bufend && (c = *patnext++) != EOS)
			अगर (c == QUOTE) {
				अगर ((c = *patnext++) == EOS) {
					c = QUOTE;
					--patnext;
				}
				*bufnext++ = c | M_PROTECT;
			} अन्यथा
				*bufnext++ = c;
	}
	*bufnext = EOS;

	अगर (flags & GLOB_BRACE)
		वापस globexp1(patbuf, pglob, &limit);
	अन्यथा
		वापस glob0(patbuf, pglob, &limit);
}

/*
 * Expand recursively a glob {} pattern. When there is no more expansion
 * invoke the standard globbing routine to glob the rest of the magic
 * characters
 */
अटल पूर्णांक
globexp1(स्थिर Char *pattern, glob_t *pglob, काष्ठा glob_lim *limitp)
{
	स्थिर Char* ptr = pattern;

	/* Protect a single {}, for find(1), like csh */
	अगर (pattern[0] == LBRACE && pattern[1] == RBRACE && pattern[2] == EOS)
		वापस glob0(pattern, pglob, limitp);

	अगर ((ptr = (स्थिर Char *) g_strchr(ptr, LBRACE)) != शून्य)
		वापस globexp2(ptr, pattern, pglob, limitp);

	वापस glob0(pattern, pglob, limitp);
}


/*
 * Recursive brace globbing helper. Tries to expand a single brace.
 * If it succeeds then it invokes globexp1 with the new pattern.
 * If it fails then it tries to glob the rest of the pattern and returns.
 */
अटल पूर्णांक
globexp2(स्थिर Char *ptr, स्थिर Char *pattern, glob_t *pglob,
    काष्ठा glob_lim *limitp)
{
	पूर्णांक     i, rv;
	Char   *lm, *ls;
	स्थिर Char *pe, *pm, *pl;
	Char    patbuf[PATH_MAX];

	/* copy part up to the brace */
	क्रम (lm = patbuf, pm = pattern; pm != ptr; *lm++ = *pm++)
		;
	*lm = EOS;
	ls = lm;

	/* Find the balanced brace */
	क्रम (i = 0, pe = ++ptr; *pe; pe++)
		अगर (*pe == LBRACKET) {
			/* Ignore everything between [] */
			क्रम (pm = pe++; *pe != RBRACKET && *pe != EOS; pe++)
				;
			अगर (*pe == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pe = pm;
			}
		} अन्यथा अगर (*pe == LBRACE)
			i++;
		अन्यथा अगर (*pe == RBRACE) {
			अगर (i == 0)
				अवरोध;
			i--;
		}

	/* Non matching braces; just glob the pattern */
	अगर (i != 0 || *pe == EOS)
		वापस glob0(patbuf, pglob, limitp);

	क्रम (i = 0, pl = pm = ptr; pm <= pe; pm++) {
		चयन (*pm) {
		हाल LBRACKET:
			/* Ignore everything between [] */
			क्रम (pl = pm++; *pm != RBRACKET && *pm != EOS; pm++)
				;
			अगर (*pm == EOS) {
				/*
				 * We could not find a matching RBRACKET.
				 * Ignore and just look for RBRACE
				 */
				pm = pl;
			}
			अवरोध;

		हाल LBRACE:
			i++;
			अवरोध;

		हाल RBRACE:
			अगर (i) {
				i--;
				अवरोध;
			}
			/* FALLTHROUGH */
		हाल COMMA:
			अगर (i && *pm == COMMA)
				अवरोध;
			अन्यथा {
				/* Append the current string */
				क्रम (lm = ls; (pl < pm); *lm++ = *pl++)
					;

				/*
				 * Append the rest of the pattern after the
				 * closing brace
				 */
				क्रम (pl = pe + 1; (*lm++ = *pl++) != EOS; )
					;

				/* Expand the current pattern */
#अगर_घोषित DEBUG
				qprintf("globexp2:", patbuf);
#पूर्ण_अगर
				rv = globexp1(patbuf, pglob, limitp);
				अगर (rv && rv != GLOB_NOMATCH)
					वापस rv;

				/* move after the comma, to the next string */
				pl = pm + 1;
			}
			अवरोध;

		शेष:
			अवरोध;
		}
	}
	वापस 0;
}



/*
 * expand tilde from the passwd file.
 */
अटल स्थिर Char *
globtilde(स्थिर Char *pattern, Char *patbuf, माप_प्रकार patbuf_len, glob_t *pglob)
{
	काष्ठा passwd *pwd;
	अक्षर *h;
	स्थिर Char *p;
	Char *b, *eb;

	अगर (*pattern != TILDE || !(pglob->gl_flags & GLOB_TILDE))
		वापस pattern;

	/* Copy up to the end of the string or / */
	eb = &patbuf[patbuf_len - 1];
	क्रम (p = pattern + 1, h = (अक्षर *) patbuf;
	    h < (अक्षर *)eb && *p && *p != SLASH; *h++ = *p++)
		;

	*h = EOS;

#अगर 0
	अगर (h == (अक्षर *)eb)
		वापस what;
#पूर्ण_अगर

	अगर (((अक्षर *) patbuf)[0] == EOS) {
		/*
		 * handle a plain ~ or ~/ by expanding $HOME
		 * first and then trying the password file
		 */
#अगर 0
		अगर (issetugid() != 0 || (h = दो_पर्या("HOME")) == शून्य) {
#पूर्ण_अगर
		अगर ((getuid() != geteuid()) || (h = दो_पर्या("HOME")) == शून्य) {
			अगर ((pwd = getpwuid(getuid())) == शून्य)
				वापस pattern;
			अन्यथा
				h = pwd->pw_dir;
		}
	} अन्यथा {
		/*
		 * Expand a ~user
		 */
		अगर ((pwd = getpwnam((अक्षर*) patbuf)) == शून्य)
			वापस pattern;
		अन्यथा
			h = pwd->pw_dir;
	}

	/* Copy the home directory */
	क्रम (b = patbuf; b < eb && *h; *b++ = *h++)
		;

	/* Append the rest of the pattern */
	जबतक (b < eb && (*b++ = *p++) != EOS)
		;
	*b = EOS;

	वापस patbuf;
}

अटल पूर्णांक
g_strncmp(स्थिर Char *s1, स्थिर अक्षर *s2, माप_प्रकार n)
{
	पूर्णांक rv = 0;

	जबतक (n--) {
		rv = *(Char *)s1 - *(स्थिर अचिन्हित अक्षर *)s2++;
		अगर (rv)
			अवरोध;
		अगर (*s1++ == '\0')
			अवरोध;
	}
	वापस rv;
}

अटल पूर्णांक
g_charclass(स्थिर Char **patternp, Char **bufnextp)
{
	स्थिर Char *pattern = *patternp + 1;
	Char *bufnext = *bufnextp;
	स्थिर Char *colon;
	काष्ठा cclass *cc;
	माप_प्रकार len;

	अगर ((colon = g_strchr(pattern, ':')) == शून्य || colon[1] != ']')
		वापस 1;	/* not a character class */

	len = (माप_प्रकार)(colon - pattern);
	क्रम (cc = cclasses; cc->name != शून्य; cc++) {
		अगर (!g_strncmp(pattern, cc->name, len) && cc->name[len] == '\0')
			अवरोध;
	}
	अगर (cc->name == शून्य)
		वापस -1;	/* invalid character class */
	*bufnext++ = M_CLASS;
	*bufnext++ = (Char)(cc - &cclasses[0]);
	*bufnextp = bufnext;
	*patternp += len + 3;

	वापस 0;
}

/*
 * The main glob() routine: compiles the pattern (optionally processing
 * quotes), calls glob1() to do the real pattern matching, and finally
 * sorts the list (unless unsorted operation is requested).  Returns 0
 * if things went well, nonzero if errors occurred.  It is not an error
 * to find no matches.
 */
अटल पूर्णांक
glob0(स्थिर Char *pattern, glob_t *pglob, काष्ठा glob_lim *limitp)
{
	स्थिर Char *qpatnext;
	पूर्णांक c, err;
	माप_प्रकार oldpathc;
	Char *bufnext, patbuf[PATH_MAX];

	qpatnext = globtilde(pattern, patbuf, PATH_MAX, pglob);
	oldpathc = pglob->gl_pathc;
	bufnext = patbuf;

	/* We don't need to check for buffer overflow any more. */
	जबतक ((c = *qpatnext++) != EOS) {
		चयन (c) {
		हाल LBRACKET:
			c = *qpatnext;
			अगर (c == NOT)
				++qpatnext;
			अगर (*qpatnext == EOS ||
			    g_strchr(qpatnext+1, RBRACKET) == शून्य) {
				*bufnext++ = LBRACKET;
				अगर (c == NOT)
					--qpatnext;
				अवरोध;
			}
			*bufnext++ = M_SET;
			अगर (c == NOT)
				*bufnext++ = M_NOT;
			c = *qpatnext++;
			करो {
				अगर (c == LBRACKET && *qpatnext == ':') {
					करो {
						err = g_charclass(&qpatnext,
						    &bufnext);
						अगर (err)
							अवरोध;
						c = *qpatnext++;
					} जबतक (c == LBRACKET && *qpatnext == ':');
					अगर (err == -1 &&
					    !(pglob->gl_flags & GLOB_NOCHECK))
						वापस GLOB_NOMATCH;
					अगर (c == RBRACKET)
						अवरोध;
				}
				*bufnext++ = CHAR(c);
				अगर (*qpatnext == RANGE &&
				    (c = qpatnext[1]) != RBRACKET) {
					*bufnext++ = M_RNG;
					*bufnext++ = CHAR(c);
					qpatnext += 2;
				}
			} जबतक ((c = *qpatnext++) != RBRACKET);
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_END;
			अवरोध;
		हाल QUESTION:
			pglob->gl_flags |= GLOB_MAGCHAR;
			*bufnext++ = M_ONE;
			अवरोध;
		हाल STAR:
			pglob->gl_flags |= GLOB_MAGCHAR;
			/* collapse adjacent stars to one,
			 * to avoid exponential behavior
			 */
			अगर (bufnext == patbuf || bufnext[-1] != M_ALL)
				*bufnext++ = M_ALL;
			अवरोध;
		शेष:
			*bufnext++ = CHAR(c);
			अवरोध;
		}
	}
	*bufnext = EOS;
#अगर_घोषित DEBUG
	qprintf("glob0:", patbuf);
#पूर्ण_अगर

	अगर ((err = glob1(patbuf, patbuf+PATH_MAX-1, pglob, limitp)) != 0)
		वापस(err);

	/*
	 * If there was no match we are going to append the pattern
	 * if GLOB_NOCHECK was specified or if GLOB_NOMAGIC was specified
	 * and the pattern did not contain any magic characters
	 * GLOB_NOMAGIC is there just for compatibility with csh.
	 */
	अगर (pglob->gl_pathc == oldpathc) {
		अगर ((pglob->gl_flags & GLOB_NOCHECK) ||
		    ((pglob->gl_flags & GLOB_NOMAGIC) &&
		    !(pglob->gl_flags & GLOB_MAGCHAR)))
			वापस(globextend(pattern, pglob, limitp, शून्य));
		अन्यथा
			वापस(GLOB_NOMATCH);
	}
	अगर (!(pglob->gl_flags & GLOB_NOSORT)) {
		अगर ((pglob->gl_flags & GLOB_KEEPSTAT)) {
			/* Keep the paths and stat info synced during sort */
			काष्ठा glob_path_stat *path_stat;
			माप_प्रकार i;
			माप_प्रकार n = pglob->gl_pathc - oldpathc;
			माप_प्रकार o = pglob->gl_offs + oldpathc;

			अगर ((path_stat = सुस्मृति(n, माप(*path_stat))) == शून्य)
				वापस GLOB_NOSPACE;
			क्रम (i = 0; i < n; i++) {
				path_stat[i].gps_path = pglob->gl_pathv[o + i];
				path_stat[i].gps_stat = pglob->gl_statv[o + i];
			}
			क्विक(path_stat, n, माप(*path_stat), compare_gps);
			क्रम (i = 0; i < n; i++) {
				pglob->gl_pathv[o + i] = path_stat[i].gps_path;
				pglob->gl_statv[o + i] = path_stat[i].gps_stat;
			}
			मुक्त(path_stat);
		} अन्यथा {
			क्विक(pglob->gl_pathv + pglob->gl_offs + oldpathc,
			    pglob->gl_pathc - oldpathc, माप(अक्षर *),
			    compare);
		}
	}
	वापस(0);
}

अटल पूर्णांक
compare(स्थिर व्योम *p, स्थिर व्योम *q)
{
	वापस(म_भेद(*(अक्षर **)p, *(अक्षर **)q));
}

अटल पूर्णांक
compare_gps(स्थिर व्योम *_p, स्थिर व्योम *_q)
{
	स्थिर काष्ठा glob_path_stat *p = (स्थिर काष्ठा glob_path_stat *)_p;
	स्थिर काष्ठा glob_path_stat *q = (स्थिर काष्ठा glob_path_stat *)_q;

	वापस(म_भेद(p->gps_path, q->gps_path));
}

अटल पूर्णांक
glob1(Char *pattern, Char *pattern_last, glob_t *pglob, काष्ठा glob_lim *limitp)
{
	Char pathbuf[PATH_MAX];

	/* A null pathname is invalid -- POSIX 1003.1 sect. 2.4. */
	अगर (*pattern == EOS)
		वापस(0);
	वापस(glob2(pathbuf, pathbuf+PATH_MAX-1,
	    pathbuf, pathbuf+PATH_MAX-1,
	    pattern, pattern_last, pglob, limitp));
}

/*
 * The functions glob2 and glob3 are mutually recursive; there is one level
 * of recursion for each segment in the pattern that contains one or more
 * meta characters.
 */
अटल पूर्णांक
glob2(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *pattern_last, glob_t *pglob, काष्ठा glob_lim *limitp)
{
	काष्ठा stat sb;
	Char *p, *q;
	पूर्णांक anymeta;

	/*
	 * Loop over pattern segments until end of pattern or until
	 * segment with meta character found.
	 */
	क्रम (anymeta = 0;;) {
		अगर (*pattern == EOS) {		/* End of pattern? */
			*pathend = EOS;

			अगर ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_stat++ >= GLOB_LIMIT_STAT) {
				त्रुटि_सं = 0;
				*pathend++ = SEP;
				*pathend = EOS;
				वापस(GLOB_NOSPACE);
			}
			अगर (g_lstat(pathbuf, &sb, pglob))
				वापस(0);

			अगर (((pglob->gl_flags & GLOB_MARK) &&
			    pathend[-1] != SEP) && (S_ISDIR(sb.st_mode) ||
			    (S_ISLNK(sb.st_mode) &&
			    (g_stat(pathbuf, &sb, pglob) == 0) &&
			    S_ISDIR(sb.st_mode)))) {
				अगर (pathend+1 > pathend_last)
					वापस (1);
				*pathend++ = SEP;
				*pathend = EOS;
			}
			++pglob->gl_matchc;
			वापस(globextend(pathbuf, pglob, limitp, &sb));
		}

		/* Find end of next segment, copy tentatively to pathend. */
		q = pathend;
		p = pattern;
		जबतक (*p != EOS && *p != SEP) {
			अगर (ismeta(*p))
				anymeta = 1;
			अगर (q+1 > pathend_last)
				वापस (1);
			*q++ = *p++;
		}

		अगर (!anymeta) {		/* No expansion, do next segment. */
			pathend = q;
			pattern = p;
			जबतक (*pattern == SEP) {
				अगर (pathend+1 > pathend_last)
					वापस (1);
				*pathend++ = *pattern++;
			}
		} अन्यथा
			/* Need expansion, recurse. */
			वापस(glob3(pathbuf, pathbuf_last, pathend,
			    pathend_last, pattern, p, pattern_last,
			    pglob, limitp));
	}
	/* NOTREACHED */
}

अटल पूर्णांक
glob3(Char *pathbuf, Char *pathbuf_last, Char *pathend, Char *pathend_last,
    Char *pattern, Char *restpattern, Char *restpattern_last, glob_t *pglob,
    काष्ठा glob_lim *limitp)
{
	काष्ठा dirent *dp;
	सूची *dirp;
	पूर्णांक err;
	अक्षर buf[PATH_MAX];

	/*
	 * The readdirfunc declaration can't be prototyped, because it is
	 * assigned, below, to two functions which are prototyped in glob.h
	 * and dirent.h as taking pointers to differently typed opaque
	 * structures.
	 */
	काष्ठा dirent *(*readdirfunc)(व्योम *);

	अगर (pathend > pathend_last)
		वापस (1);
	*pathend = EOS;
	त्रुटि_सं = 0;

	अगर ((dirp = g_opendir(pathbuf, pglob)) == शून्य) {
		/* TODO: don't call for ENOENT or ENOTDIR? */
		अगर (pglob->gl_errfunc) {
			अगर (g_Ctoc(pathbuf, buf, माप(buf)))
				वापस(GLOB_ABORTED);
			अगर (pglob->gl_errfunc(buf, त्रुटि_सं) ||
			    pglob->gl_flags & GLOB_ERR)
				वापस(GLOB_ABORTED);
		}
		वापस(0);
	}

	err = 0;

	/* Search directory for matching names. */
	अगर (pglob->gl_flags & GLOB_ALTDIRFUNC)
		readdirfunc = pglob->gl_readdir;
	अन्यथा
		readdirfunc = (काष्ठा dirent *(*)(व्योम *))सूची_पढ़ो;
	जबतक ((dp = (*readdirfunc)(dirp))) {
		u_char *sc;
		Char *dc;

		अगर ((pglob->gl_flags & GLOB_LIMIT) &&
		    limitp->glim_readdir++ >= GLOB_LIMIT_READDIR) {
			त्रुटि_सं = 0;
			*pathend++ = SEP;
			*pathend = EOS;
			err = GLOB_NOSPACE;
			अवरोध;
		}

		/* Initial DOT must be matched literally. */
		अगर (dp->d_name[0] == DOT && *pattern != DOT)
			जारी;
		dc = pathend;
		sc = (u_char *) dp->d_name;
		जबतक (dc < pathend_last && (*dc++ = *sc++) != EOS)
			;
		अगर (dc >= pathend_last) {
			*dc = EOS;
			err = 1;
			अवरोध;
		}

		अगर (!match(pathend, pattern, restpattern)) {
			*pathend = EOS;
			जारी;
		}
		err = glob2(pathbuf, pathbuf_last, --dc, pathend_last,
		    restpattern, restpattern_last, pglob, limitp);
		अगर (err)
			अवरोध;
	}

	अगर (pglob->gl_flags & GLOB_ALTDIRFUNC)
		(*pglob->gl_closedir)(dirp);
	अन्यथा
		बंद_सूची(dirp);
	वापस(err);
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
अटल पूर्णांक
globextend(स्थिर Char *path, glob_t *pglob, काष्ठा glob_lim *limitp,
    काष्ठा stat *sb)
{
	अक्षर **pathv;
	माप_प्रकार i, newn, len;
	अक्षर *copy = शून्य;
	स्थिर Char *p;
	काष्ठा stat **statv;

	newn = 2 + pglob->gl_pathc + pglob->gl_offs;
	अगर (pglob->gl_offs >= SSIZE_MAX ||
	    pglob->gl_pathc >= SSIZE_MAX ||
	    newn >= SSIZE_MAX ||
	    SIZE_MAX / माप(*pathv) <= newn ||
	    SIZE_MAX / माप(*statv) <= newn) {
 nospace:
		क्रम (i = pglob->gl_offs; i < newn - 2; i++) {
			अगर (pglob->gl_pathv && pglob->gl_pathv[i])
				मुक्त(pglob->gl_pathv[i]);
			अगर ((pglob->gl_flags & GLOB_KEEPSTAT) != 0 &&
			    pglob->gl_pathv && pglob->gl_pathv[i])
				मुक्त(pglob->gl_statv[i]);
		}
		मुक्त(pglob->gl_pathv);
		pglob->gl_pathv = शून्य;
		मुक्त(pglob->gl_statv);
		pglob->gl_statv = शून्य;
		वापस(GLOB_NOSPACE);
	}

	pathv = reallocarray(pglob->gl_pathv, newn, माप(*pathv));
	अगर (pathv == शून्य)
		जाओ nospace;
	अगर (pglob->gl_pathv == शून्य && pglob->gl_offs > 0) {
		/* first time around -- clear initial gl_offs items */
		pathv += pglob->gl_offs;
		क्रम (i = pglob->gl_offs; i > 0; i--)
			*--pathv = शून्य;
	}
	pglob->gl_pathv = pathv;

	अगर ((pglob->gl_flags & GLOB_KEEPSTAT) != 0) {
		statv = reallocarray(pglob->gl_statv, newn, माप(*statv));
		अगर (statv == शून्य)
			जाओ nospace;
		अगर (pglob->gl_statv == शून्य && pglob->gl_offs > 0) {
			/* first time around -- clear initial gl_offs items */
			statv += pglob->gl_offs;
			क्रम (i = pglob->gl_offs; i > 0; i--)
				*--statv = शून्य;
		}
		pglob->gl_statv = statv;
		अगर (sb == शून्य)
			statv[pglob->gl_offs + pglob->gl_pathc] = शून्य;
		अन्यथा {
			limitp->glim_malloc += माप(**statv);
			अगर ((pglob->gl_flags & GLOB_LIMIT) &&
			    limitp->glim_malloc >= GLOB_LIMIT_MALLOC) {
				त्रुटि_सं = 0;
				वापस(GLOB_NOSPACE);
			}
			अगर ((statv[pglob->gl_offs + pglob->gl_pathc] =
			    दो_स्मृति(माप(**statv))) == शून्य)
				जाओ copy_error;
			स_नकल(statv[pglob->gl_offs + pglob->gl_pathc], sb,
			    माप(*sb));
		}
		statv[pglob->gl_offs + pglob->gl_pathc + 1] = शून्य;
	}

	क्रम (p = path; *p++;)
		;
	len = (माप_प्रकार)(p - path);
	limitp->glim_malloc += len;
	अगर ((copy = दो_स्मृति(len)) != शून्य) {
		अगर (g_Ctoc(path, copy, len)) {
			मुक्त(copy);
			वापस(GLOB_NOSPACE);
		}
		pathv[pglob->gl_offs + pglob->gl_pathc++] = copy;
	}
	pathv[pglob->gl_offs + pglob->gl_pathc] = शून्य;

	अगर ((pglob->gl_flags & GLOB_LIMIT) &&
	    (newn * माप(*pathv)) + limitp->glim_malloc >
	    GLOB_LIMIT_MALLOC) {
		त्रुटि_सं = 0;
		वापस(GLOB_NOSPACE);
	}
 copy_error:
	वापस(copy == शून्य ? GLOB_NOSPACE : 0);
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
अटल पूर्णांक
match(Char *name, Char *pat, Char *patend)
{
	पूर्णांक ok, negate_range;
	Char c, k;
	Char *nextp = शून्य;
	Char *nextn = शून्य;

loop:
	जबतक (pat < patend) {
		c = *pat++;
		चयन (c & M_MASK) {
		हाल M_ALL:
			जबतक (pat < patend && (*pat & M_MASK) == M_ALL)
				pat++;	/* eat consecutive '*' */
			अगर (pat == patend)
				वापस(1);
			अगर (*name == EOS)
				वापस(0);
			nextn = name + 1;
			nextp = pat - 1;
			अवरोध;
		हाल M_ONE:
			अगर (*name++ == EOS)
				जाओ fail;
			अवरोध;
		हाल M_SET:
			ok = 0;
			अगर ((k = *name++) == EOS)
				जाओ fail;
			अगर ((negate_range = ((*pat & M_MASK) == M_NOT)) != EOS)
				++pat;
			जबतक (((c = *pat++) & M_MASK) != M_END) {
				अगर ((c & M_MASK) == M_CLASS) {
					Char idx = *pat & M_MASK;
					अगर (idx < NCCLASSES &&
					    cclasses[idx].isctype(k))
						ok = 1;
					++pat;
				}
				अगर ((*pat & M_MASK) == M_RNG) {
					अगर (c <= k && k <= pat[1])
						ok = 1;
					pat += 2;
				} अन्यथा अगर (c == k)
					ok = 1;
			}
			अगर (ok == negate_range)
				जाओ fail;
			अवरोध;
		शेष:
			अगर (*name++ != c)
				जाओ fail;
			अवरोध;
		}
	}
	अगर (*name == EOS)
		वापस(1);

fail:
	अगर (nextn) {
		pat = nextp;
		name = nextn;
		जाओ loop;
	}
	वापस(0);
}

/* Free allocated data belonging to a glob_t structure. */
व्योम
globfree(glob_t *pglob)
{
	माप_प्रकार i;
	अक्षर **pp;

	अगर (pglob->gl_pathv != शून्य) {
		pp = pglob->gl_pathv + pglob->gl_offs;
		क्रम (i = pglob->gl_pathc; i--; ++pp)
			मुक्त(*pp);
		मुक्त(pglob->gl_pathv);
		pglob->gl_pathv = शून्य;
	}
	अगर (pglob->gl_statv != शून्य) {
		क्रम (i = 0; i < pglob->gl_pathc; i++) {
			मुक्त(pglob->gl_statv[i]);
		}
		मुक्त(pglob->gl_statv);
		pglob->gl_statv = शून्य;
	}
}

अटल सूची *
g_opendir(Char *str, glob_t *pglob)
{
	अक्षर buf[PATH_MAX];

	अगर (!*str)
		strlcpy(buf, ".", माप buf);
	अन्यथा {
		अगर (g_Ctoc(str, buf, माप(buf)))
			वापस(शून्य);
	}

	अगर (pglob->gl_flags & GLOB_ALTDIRFUNC)
		वापस((*pglob->gl_opendir)(buf));

	वापस(सूची_खोलो(buf));
}

अटल पूर्णांक
g_lstat(Char *fn, काष्ठा stat *sb, glob_t *pglob)
{
	अक्षर buf[PATH_MAX];

	अगर (g_Ctoc(fn, buf, माप(buf)))
		वापस(-1);
	अगर (pglob->gl_flags & GLOB_ALTDIRFUNC)
		वापस((*pglob->gl_lstat)(buf, sb));
	वापस(lstat(buf, sb));
}

अटल पूर्णांक
g_stat(Char *fn, काष्ठा stat *sb, glob_t *pglob)
{
	अक्षर buf[PATH_MAX];

	अगर (g_Ctoc(fn, buf, माप(buf)))
		वापस(-1);
	अगर (pglob->gl_flags & GLOB_ALTDIRFUNC)
		वापस((*pglob->gl_stat)(buf, sb));
	वापस(stat(buf, sb));
}

अटल Char *
g_strchr(स्थिर Char *str, पूर्णांक ch)
{
	करो {
		अगर (*str == ch)
			वापस ((Char *)str);
	} जबतक (*str++);
	वापस (शून्य);
}

अटल पूर्णांक
g_Ctoc(स्थिर Char *str, अक्षर *buf, माप_प्रकार len)
{

	जबतक (len--) {
		अगर ((*buf++ = *str++) == EOS)
			वापस (0);
	}
	वापस (1);
}

#अगर_घोषित DEBUG
अटल व्योम
qprintf(स्थिर अक्षर *str, Char *s)
{
	Char *p;

	(व्योम)म_लिखो("%s:\n", str);
	क्रम (p = s; *p; p++)
		(व्योम)म_लिखो("%c", CHAR(*p));
	(व्योम)म_लिखो("\n");
	क्रम (p = s; *p; p++)
		(व्योम)म_लिखो("%c", *p & M_PROTECT ? '"' : ' ');
	(व्योम)म_लिखो("\n");
	क्रम (p = s; *p; p++)
		(व्योम)म_लिखो("%c", ismeta(*p) ? '_' : ' ');
	(व्योम)म_लिखो("\n");
}
#पूर्ण_अगर

#पूर्ण_अगर /* !defined(HAVE_GLOB) || !defined(GLOB_HAS_ALTDIRFUNC) ||
          !defined(GLOB_HAS_GL_MATCHC) || !defined(GLOB_HAS_GL_STATV) */
