/*
 * Copyright (c) 2000, 2001, 2011, 2013 Corinna Vinschen <vinschen@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Created: Sat Sep 02 12:17:00 2000 cv
 *
 * This file contains functions for forcing opened file descriptors to
 * binary mode on Windows systems.
 */

#घोषणा NO_द्विआधारी_OPEN	/* Avoid redefining open to binary_open for this file */
#समावेश "includes.h"

#अगर_घोषित HAVE_CYGWIN

#समावेश <sys/types.h>
#समावेश <fcntl.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <wchar.h>
#समावेश <wctype.h>

#समावेश "xmalloc.h"

पूर्णांक
द्विआधारी_open(स्थिर अक्षर *filename, पूर्णांक flags, ...)
{
	बहु_सूची ap;
	mode_t mode;

	बहु_शुरू(ap, flags);
	mode = बहु_तर्क(ap, mode_t);
	बहु_पूर्ण(ap);
	वापस (खोलो(filename, flags | O_द्विआधारी, mode));
}

पूर्णांक
check_ntsec(स्थिर अक्षर *filename)
{
	वापस (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

स्थिर अक्षर *
cygwin_ssh_privsep_user()
{
  अटल अक्षर cyg_privsep_user[DNLEN + UNLEN + 2];

  अगर (!cyg_privsep_user[0])
    {
#अगर_घोषित CW_CYGNAME_FROM_WINNAME
      अगर (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   माप cyg_privsep_user) != 0)
#पूर्ण_अगर
	strlcpy(cyg_privsep_user, "sshd", माप(cyg_privsep_user));
    }
  वापस cyg_privsep_user;
}

#घोषणा NL(x) x, (माप (x) - 1)
#घोषणा WENV_SIZ (माप (wenv_arr) / माप (wenv_arr[0]))

अटल काष्ठा wenv {
	स्थिर अक्षर *name;
	माप_प्रकार namelen;
} wenv_arr[] = {
	{ NL("ALLUSERSPROFILE=") },
	{ NL("COMPUTERNAME=") },
	{ NL("COMSPEC=") },
	{ NL("CYGWIN=") },
	{ NL("OS=") },
	{ NL("PATH=") },
	{ NL("PATHEXT=") },
	{ NL("PROGRAMFILES=") },
	{ NL("SYSTEMDRIVE=") },
	{ NL("SYSTEMROOT=") },
	{ NL("WINDIR=") }
};

अक्षर **
fetch_windows_environment(व्योम)
{
	अक्षर **e, **p;
	अचिन्हित पूर्णांक i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, माप(अक्षर *));
	क्रम (e = environ; *e != शून्य; ++e) {
		क्रम (i = 0; i < WENV_SIZ; ++i) {
			अगर (!म_भेदन(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = शून्य;
	वापस p;
}

व्योम
free_windows_environment(अक्षर **p)
{
	मुक्त(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

अटल पूर्णांक
__match_pattern (स्थिर ब_अक्षर_प्रकार *s, स्थिर ब_अक्षर_प्रकार *pattern)
{
	क्रम (;;) {
		/* If at end of pattern, accept if also at end of string. */
		अगर (!*pattern)
			वापस !*s;

		अगर (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			अगर (!*pattern)
				वापस 1;

			/* If next character in pattern is known, optimize. */
			अगर (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				क्रम (; *s; s++)
					अगर (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						वापस 1;
				/* Failed. */
				वापस 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			क्रम (; *s; s++)
				अगर (__match_pattern(s, pattern))
					वापस 1;
			/* Failed. */
			वापस 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		अगर (!*s)
			वापस 0;

		/* Check if the next character of the string is acceptable. */
		अगर (*pattern != '?' && towlower(*pattern) != towlower(*s))
			वापस 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

अटल पूर्णांक
_match_pattern(स्थिर अक्षर *s, स्थिर अक्षर *pattern)
{
	ब_अक्षर_प्रकार *ws;
	ब_अक्षर_प्रकार *wpattern;
	माप_प्रकार len;
	पूर्णांक ret;

	अगर ((len = mbstowcs(शून्य, s, 0)) == (माप_प्रकार) -1)
		वापस 0;
	ws = (ब_अक्षर_प्रकार *) xcalloc(len + 1, माप (ब_अक्षर_प्रकार));
	mbstowcs(ws, s, len + 1);
	अगर ((len = mbstowcs(शून्य, pattern, 0)) == (माप_प्रकार) -1) {
		मुक्त(ws);
		वापस 0;
	}
	wpattern = (ब_अक्षर_प्रकार *) xcalloc(len + 1, माप (ब_अक्षर_प्रकार));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	मुक्त(ws);
	मुक्त(wpattern);
	वापस ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
पूर्णांक
cygwin_ug_match_pattern_list(स्थिर अक्षर *string, स्थिर अक्षर *pattern)
{
	अक्षर sub[1024];
	पूर्णांक negated;
	पूर्णांक got_positive;
	माप_प्रकार i, subi, len = म_माप(pattern);

	got_positive = 0;
	क्रम (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		अगर (pattern[i] == '!') {
			negated = 1;
			i++;
		} अन्यथा
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		क्रम (subi = 0;
		    i < len && subi < माप(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		अगर (subi >= माप(sub) - 1)
			वापस 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		अगर (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		अगर (_match_pattern(string, sub)) {
			अगर (negated)
				वापस -1;		/* Negative */
			अन्यथा
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	वापस got_positive;
}

#पूर्ण_अगर /* HAVE_CYGWIN */
