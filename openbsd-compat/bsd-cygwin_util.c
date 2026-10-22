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

ကိန်းပြည့်
binary_open(const var_na *filename, ကိန်းပြည့် flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	ပြန်ပေး (open(filename, flags | O_BINARY, mode));
}

ကိန်းပြည့်
check_ntsec(const var_na *filename)
{
	ပြန်ပေး (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

const var_na *
cygwin_ssh_privsep_user()
{
  static var_na cyg_privsep_user[DNLEN + UNLEN + 2];

  အကယ်၍ (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      အကယ်၍ (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   parimaa_na cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", parimaa_na(cyg_privsep_user));
    }
  ပြန်ပေး cyg_privsep_user;
}

#define NL(x) x, (parimaa_na (x) - 1)
#define WENV_SIZ (parimaa_na (wenv_arr) / parimaa_na (wenv_arr[0]))

static sa_nracanaa wenv {
	const var_na *name;
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

var_na **
fetch_windows_environment(void)
{
	var_na **e, **p;
	unsigned ကိန်းပြည့် i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, parimaa_na(var_na *));
	အတွက် (e = environ; *e != NULL; ++e) {
		အတွက် (i = 0; i < WENV_SIZ; ++i) {
			အကယ်၍ (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = NULL;
	ပြန်ပေး p;
}

void
free_windows_environment(var_na **p)
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

static ကိန်းပြည့်
__match_pattern (const wchar_t *s, const wchar_t *pattern)
{
	အတွက် (;;) {
		/* If at end of pattern, accept if also at end of string. */
		အကယ်၍ (!*pattern)
			ပြန်ပေး !*s;

		အကယ်၍ (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			အကယ်၍ (!*pattern)
				ပြန်ပေး 1;

			/* If next character in pattern is known, optimize. */
			အကယ်၍ (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				အတွက် (; *s; s++)
					အကယ်၍ (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						ပြန်ပေး 1;
				/* Failed. */
				ပြန်ပေး 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			အတွက် (; *s; s++)
				အကယ်၍ (__match_pattern(s, pattern))
					ပြန်ပေး 1;
			/* Failed. */
			ပြန်ပေး 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		အကယ်၍ (!*s)
			ပြန်ပေး 0;

		/* Check if the next character of the string is acceptable. */
		အကယ်၍ (*pattern != '?' && towlower(*pattern) != towlower(*s))
			ပြန်ပေး 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

static ကိန်းပြည့်
_match_pattern(const var_na *s, const var_na *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	ကိန်းပြည့် ret;

	အကယ်၍ ((len = mbstowcs(NULL, s, 0)) == (size_t) -1)
		ပြန်ပေး 0;
	ws = (wchar_t *) xcalloc(len + 1, parimaa_na (wchar_t));
	mbstowcs(ws, s, len + 1);
	အကယ်၍ ((len = mbstowcs(NULL, pattern, 0)) == (size_t) -1) {
		free(ws);
		ပြန်ပေး 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, parimaa_na (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	free(ws);
	free(wpattern);
	ပြန်ပေး ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ကိန်းပြည့်
cygwin_ug_match_pattern_list(const var_na *string, const var_na *pattern)
{
	var_na sub[1024];
	ကိန်းပြည့် negated;
	ကိန်းပြည့် got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	အတွက် (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		အကယ်၍ (pattern[i] == '!') {
			negated = 1;
			i++;
		} မဟုတ်ပါက
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		အတွက် (subi = 0;
		    i < len && subi < parimaa_na(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		အကယ်၍ (subi >= parimaa_na(sub) - 1)
			ပြန်ပေး 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		အကယ်၍ (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		အကယ်၍ (_match_pattern(string, sub)) {
			အကယ်၍ (negated)
				ပြန်ပေး -1;		/* Negative */
			မဟုတ်ပါက
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ပြန်ပေး got_positive;
}

#endif /* HAVE_CYGWIN */
