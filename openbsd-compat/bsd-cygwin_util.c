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

整数
binary_open(const char *filename, 整数 flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	返回 (open(filename, flags | O_BINARY, mode));
}

整数
check_ntsec(const char *filename)
{
	返回 (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

const char *
cygwin_ssh_privsep_user()
{
  static char cyg_privsep_user[DNLEN + UNLEN + 2];

  如果 (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      如果 (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   sizeof cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", sizeof(cyg_privsep_user));
    }
  返回 cyg_privsep_user;
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
	unsigned 整数 i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, sizeof(char *));
	为 (e = environ; *e != NULL; ++e) {
		为 (i = 0; i < WENV_SIZ; ++i) {
			如果 (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = NULL;
	返回 p;
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

static 整数
__match_pattern (const wchar_t *s, const wchar_t *pattern)
{
	为 (;;) {
		/* If at end of pattern, accept if also at end of string. */
		如果 (!*pattern)
			返回 !*s;

		如果 (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			如果 (!*pattern)
				返回 1;

			/* If next character in pattern is known, optimize. */
			如果 (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				为 (; *s; s++)
					如果 (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						返回 1;
				/* Failed. */
				返回 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			为 (; *s; s++)
				如果 (__match_pattern(s, pattern))
					返回 1;
			/* Failed. */
			返回 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		如果 (!*s)
			返回 0;

		/* Check if the next character of the string is acceptable. */
		如果 (*pattern != '?' && towlower(*pattern) != towlower(*s))
			返回 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

static 整数
_match_pattern(const char *s, const char *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	整数 ret;

	如果 ((len = mbstowcs(NULL, s, 0)) == (size_t) -1)
		返回 0;
	ws = (wchar_t *) xcalloc(len + 1, sizeof (wchar_t));
	mbstowcs(ws, s, len + 1);
	如果 ((len = mbstowcs(NULL, pattern, 0)) == (size_t) -1) {
		free(ws);
		返回 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, sizeof (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	free(ws);
	free(wpattern);
	返回 ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
整数
cygwin_ug_match_pattern_list(const char *string, const char *pattern)
{
	char sub[1024];
	整数 negated;
	整数 got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	为 (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		如果 (pattern[i] == '!') {
			negated = 1;
			i++;
		} 否则
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		为 (subi = 0;
		    i < len && subi < sizeof(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		如果 (subi >= sizeof(sub) - 1)
			返回 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		如果 (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		如果 (_match_pattern(string, sub)) {
			如果 (negated)
				返回 -1;		/* Negative */
			否则
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	返回 got_positive;
}

#endif /* HAVE_CYGWIN */
