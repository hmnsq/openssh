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

पूर्णाङ्क
द्विमान_open(ध्रुव वर्ण *filename, पूर्णाङ्क flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	पटिनिवत्त (open(filename, flags | O_द्विमान, mode));
}

पूर्णाङ्क
check_ntsec(ध्रुव वर्ण *filename)
{
	पटिनिवत्त (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ध्रुव वर्ण *
cygwin_ssh_privsep_user()
{
  स्थिर वर्ण cyg_privsep_user[DNLEN + UNLEN + 2];

  सचे (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      सचे (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   परिमाण cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", परिमाण(cyg_privsep_user));
    }
  पटिनिवत्त cyg_privsep_user;
}

#define NL(x) x, (परिमाण (x) - 1)
#define WENV_SIZ (परिमाण (wenv_arr) / परिमाण (wenv_arr[0]))

स्थिर संरचना wenv {
	ध्रुव वर्ण *name;
	size_t namelen;
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

वर्ण **
fetch_windows_environment(शून्य)
{
	वर्ण **e, **p;
	unsigned पूर्णाङ्क i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, परिमाण(वर्ण *));
	अत्थाय (e = environ; *e != रिक्त; ++e) {
		अत्थाय (i = 0; i < WENV_SIZ; ++i) {
			सचे (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = रिक्त;
	पटिनिवत्त p;
}

शून्य
free_windows_environment(वर्ण **p)
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

स्थिर पूर्णाङ्क
__match_pattern (ध्रुव wchar_t *s, ध्रुव wchar_t *pattern)
{
	अत्थाय (;;) {
		/* If at end of pattern, accept if also at end of string. */
		सचे (!*pattern)
			पटिनिवत्त !*s;

		सचे (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			सचे (!*pattern)
				पटिनिवत्त 1;

			/* If next character in pattern is known, optimize. */
			सचे (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				अत्थाय (; *s; s++)
					सचे (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						पटिनिवत्त 1;
				/* Failed. */
				पटिनिवत्त 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			अत्थाय (; *s; s++)
				सचे (__match_pattern(s, pattern))
					पटिनिवत्त 1;
			/* Failed. */
			पटिनिवत्त 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		सचे (!*s)
			पटिनिवत्त 0;

		/* Check if the next character of the string is acceptable. */
		सचे (*pattern != '?' && towlower(*pattern) != towlower(*s))
			पटिनिवत्त 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

स्थिर पूर्णाङ्क
_match_pattern(ध्रुव वर्ण *s, ध्रुव वर्ण *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	पूर्णाङ्क ret;

	सचे ((len = mbstowcs(रिक्त, s, 0)) == (size_t) -1)
		पटिनिवत्त 0;
	ws = (wchar_t *) xcalloc(len + 1, परिमाण (wchar_t));
	mbstowcs(ws, s, len + 1);
	सचे ((len = mbstowcs(रिक्त, pattern, 0)) == (size_t) -1) {
		मुक्त(ws);
		पटिनिवत्त 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, परिमाण (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	मुक्त(ws);
	मुक्त(wpattern);
	पटिनिवत्त ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
पूर्णाङ्क
cygwin_ug_match_pattern_list(ध्रुव वर्ण *string, ध्रुव वर्ण *pattern)
{
	वर्ण sub[1024];
	पूर्णाङ्क negated;
	पूर्णाङ्क got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	अत्थाय (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		सचे (pattern[i] == '!') {
			negated = 1;
			i++;
		} अञ्ञथा
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		अत्थाय (subi = 0;
		    i < len && subi < परिमाण(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		सचे (subi >= परिमाण(sub) - 1)
			पटिनिवत्त 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		सचे (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		सचे (_match_pattern(string, sub)) {
			सचे (negated)
				पटिनिवत्त -1;		/* Negative */
			अञ्ञथा
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	पटिनिवत्त got_positive;
}

#endif /* HAVE_CYGWIN */
