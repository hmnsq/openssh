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

#define NO_द्विमान_OPEN	/* Avoid redefining open to binary_open for this file */
#अन्तर्भाव "includes.h"

#ifdef HAVE_CYGWIN

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <wchar.h>
#अन्तर्भाव <wctype.h>

#अन्तर्भाव "xmalloc.h"

पूर्णांक
द्विमान_open(स्थिरांक अक्षर *filename, पूर्णांक flags, ...)
{
	बहु_सूची ap;
	mode_t mode;

	बहु_शुरू(ap, flags);
	mode = बहु_तर्क(ap, mode_t);
	बहु_पूर्ण(ap);
	परत (खोलो(filename, flags | O_द्विमान, mode));
}

पूर्णांक
check_ntsec(स्थिरांक अक्षर *filename)
{
	परत (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

स्थिरांक अक्षर *
cygwin_ssh_privsep_user()
{
  स्थिर अक्षर cyg_privsep_user[DNLEN + UNLEN + 2];

  जर (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      जर (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   आकार cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", आकार(cyg_privsep_user));
    }
  परत cyg_privsep_user;
}

#define NL(x) x, (आकार (x) - 1)
#define WENV_SIZ (आकार (wenv_arr) / आकार (wenv_arr[0]))

स्थिर संरचना wenv {
	स्थिरांक अक्षर *name;
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
fetch_windows_environment(शून्य)
{
	अक्षर **e, **p;
	अचिन्हित पूर्णांक i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, आकार(अक्षर *));
	साठी (e = environ; *e != रिक्त; ++e) {
		साठी (i = 0; i < WENV_SIZ; ++i) {
			जर (!म_भेदन(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = रिक्त;
	परत p;
}

शून्य
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

स्थिर पूर्णांक
__match_pattern (स्थिरांक ब_अक्षर_प्रकार *s, स्थिरांक ब_अक्षर_प्रकार *pattern)
{
	साठी (;;) {
		/* If at end of pattern, accept if also at end of string. */
		जर (!*pattern)
			परत !*s;

		जर (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			जर (!*pattern)
				परत 1;

			/* If next character in pattern is known, optimize. */
			जर (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				साठी (; *s; s++)
					जर (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						परत 1;
				/* Failed. */
				परत 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			साठी (; *s; s++)
				जर (__match_pattern(s, pattern))
					परत 1;
			/* Failed. */
			परत 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		जर (!*s)
			परत 0;

		/* Check if the next character of the string is acceptable. */
		जर (*pattern != '?' && towlower(*pattern) != towlower(*s))
			परत 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

स्थिर पूर्णांक
_match_pattern(स्थिरांक अक्षर *s, स्थिरांक अक्षर *pattern)
{
	ब_अक्षर_प्रकार *ws;
	ब_अक्षर_प्रकार *wpattern;
	माप_प्रकार len;
	पूर्णांक ret;

	जर ((len = mbstowcs(रिक्त, s, 0)) == (माप_प्रकार) -1)
		परत 0;
	ws = (ब_अक्षर_प्रकार *) xcalloc(len + 1, आकार (ब_अक्षर_प्रकार));
	mbstowcs(ws, s, len + 1);
	जर ((len = mbstowcs(रिक्त, pattern, 0)) == (माप_प्रकार) -1) {
		मुक्त(ws);
		परत 0;
	}
	wpattern = (ब_अक्षर_प्रकार *) xcalloc(len + 1, आकार (ब_अक्षर_प्रकार));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	मुक्त(ws);
	मुक्त(wpattern);
	परत ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
पूर्णांक
cygwin_ug_match_pattern_list(स्थिरांक अक्षर *string, स्थिरांक अक्षर *pattern)
{
	अक्षर sub[1024];
	पूर्णांक negated;
	पूर्णांक got_positive;
	माप_प्रकार i, subi, len = म_माप(pattern);

	got_positive = 0;
	साठी (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		जर (pattern[i] == '!') {
			negated = 1;
			i++;
		} अन्यथा
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		साठी (subi = 0;
		    i < len && subi < आकार(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		जर (subi >= आकार(sub) - 1)
			परत 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		जर (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		जर (_match_pattern(string, sub)) {
			जर (negated)
				परत -1;		/* Negative */
			अन्यथा
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	परत got_positive;
}

#endif /* HAVE_CYGWIN */
