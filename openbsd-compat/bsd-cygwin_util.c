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

#define NO_BINARY_OPEN	/* Avoid redefining open to binary_open for this file */
#include "includes.h"

#ifdef HAVE_CYGWIN

#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <wchar.h>
#include <wctype.h>

#include "xmalloc.h"

정수
binary_open(const char *filename, 정수 flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	반환 (open(filename, flags | O_BINARY, mode));
}

정수
check_ntsec(const char *filename)
{
	반환 (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

const char *
cygwin_ssh_privsep_user()
{
  static char cyg_privsep_user[DNLEN + UNLEN + 2];

  만약 (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      만약 (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   sizeof cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", sizeof(cyg_privsep_user));
    }
  반환 cyg_privsep_user;
}

#define NL(x) x, (sizeof (x) - 1)
#define WENV_SIZ (sizeof (wenv_arr) / sizeof (wenv_arr[0]))

static struct wenv {
	const char *name;
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

char **
fetch_windows_environment(void)
{
	char **e, **p;
	unsigned 정수 i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, sizeof(char *));
	위해 (e = environ; *e != NULL; ++e) {
		위해 (i = 0; i < WENV_SIZ; ++i) {
			만약 (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = NULL;
	반환 p;
}

void
free_windows_environment(char **p)
{
	free(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

static 정수
__match_pattern (const wchar_t *s, const wchar_t *pattern)
{
	위해 (;;) {
		/* If at end of pattern, accept if also at end of string. */
		만약 (!*pattern)
			반환 !*s;

		만약 (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			만약 (!*pattern)
				반환 1;

			/* If next character in pattern is known, optimize. */
			만약 (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				위해 (; *s; s++)
					만약 (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						반환 1;
				/* Failed. */
				반환 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			위해 (; *s; s++)
				만약 (__match_pattern(s, pattern))
					반환 1;
			/* Failed. */
			반환 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		만약 (!*s)
			반환 0;

		/* Check if the next character of the string is acceptable. */
		만약 (*pattern != '?' && towlower(*pattern) != towlower(*s))
			반환 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

static 정수
_match_pattern(const char *s, const char *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	정수 ret;

	만약 ((len = mbstowcs(NULL, s, 0)) == (size_t) -1)
		반환 0;
	ws = (wchar_t *) xcalloc(len + 1, sizeof (wchar_t));
	mbstowcs(ws, s, len + 1);
	만약 ((len = mbstowcs(NULL, pattern, 0)) == (size_t) -1) {
		free(ws);
		반환 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, sizeof (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	free(ws);
	free(wpattern);
	반환 ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
정수
cygwin_ug_match_pattern_list(const char *string, const char *pattern)
{
	char sub[1024];
	정수 negated;
	정수 got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	위해 (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		만약 (pattern[i] == '!') {
			negated = 1;
			i++;
		} 아니면
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		위해 (subi = 0;
		    i < len && subi < sizeof(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		만약 (subi >= sizeof(sub) - 1)
			반환 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		만약 (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		만약 (_match_pattern(string, sub)) {
			만약 (negated)
				반환 -1;		/* Negative */
			아니면
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	반환 got_positive;
}

#endif /* HAVE_CYGWIN */
