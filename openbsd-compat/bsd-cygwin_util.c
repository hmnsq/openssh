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

ຈຳນວນເຕັມ
binary_open(const var_na *filename, ຈຳນວນເຕັມ flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	ສົ່ງຄືນ (open(filename, flags | O_BINARY, mode));
}

ຈຳນວນເຕັມ
check_ntsec(const var_na *filename)
{
	ສົ່ງຄືນ (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

const var_na *
cygwin_ssh_privsep_user()
{
  static var_na cyg_privsep_user[DNLEN + UNLEN + 2];

  ຖ້າ (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      ຖ້າ (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   parimaa_na cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", parimaa_na(cyg_privsep_user));
    }
  ສົ່ງຄືນ cyg_privsep_user;
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
	unsigned ຈຳນວນເຕັມ i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, parimaa_na(var_na *));
	ສຳລັບ (e = environ; *e != NULL; ++e) {
		ສຳລັບ (i = 0; i < WENV_SIZ; ++i) {
			ຖ້າ (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = NULL;
	ສົ່ງຄືນ p;
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

static ຈຳນວນເຕັມ
__match_pattern (const wchar_t *s, const wchar_t *pattern)
{
	ສຳລັບ (;;) {
		/* If at end of pattern, accept if also at end of string. */
		ຖ້າ (!*pattern)
			ສົ່ງຄືນ !*s;

		ຖ້າ (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			ຖ້າ (!*pattern)
				ສົ່ງຄືນ 1;

			/* If next character in pattern is known, optimize. */
			ຖ້າ (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				ສຳລັບ (; *s; s++)
					ຖ້າ (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						ສົ່ງຄືນ 1;
				/* Failed. */
				ສົ່ງຄືນ 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			ສຳລັບ (; *s; s++)
				ຖ້າ (__match_pattern(s, pattern))
					ສົ່ງຄືນ 1;
			/* Failed. */
			ສົ່ງຄືນ 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		ຖ້າ (!*s)
			ສົ່ງຄືນ 0;

		/* Check if the next character of the string is acceptable. */
		ຖ້າ (*pattern != '?' && towlower(*pattern) != towlower(*s))
			ສົ່ງຄືນ 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

static ຈຳນວນເຕັມ
_match_pattern(const var_na *s, const var_na *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	ຈຳນວນເຕັມ ret;

	ຖ້າ ((len = mbstowcs(NULL, s, 0)) == (size_t) -1)
		ສົ່ງຄືນ 0;
	ws = (wchar_t *) xcalloc(len + 1, parimaa_na (wchar_t));
	mbstowcs(ws, s, len + 1);
	ຖ້າ ((len = mbstowcs(NULL, pattern, 0)) == (size_t) -1) {
		free(ws);
		ສົ່ງຄືນ 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, parimaa_na (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	free(ws);
	free(wpattern);
	ສົ່ງຄືນ ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ຈຳນວນເຕັມ
cygwin_ug_match_pattern_list(const var_na *string, const var_na *pattern)
{
	var_na sub[1024];
	ຈຳນວນເຕັມ negated;
	ຈຳນວນເຕັມ got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	ສຳລັບ (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ຖ້າ (pattern[i] == '!') {
			negated = 1;
			i++;
		} ບໍ່ດັ່ງນັ້ນ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		ສຳລັບ (subi = 0;
		    i < len && subi < parimaa_na(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		ຖ້າ (subi >= parimaa_na(sub) - 1)
			ສົ່ງຄືນ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ຖ້າ (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ຖ້າ (_match_pattern(string, sub)) {
			ຖ້າ (negated)
				ສົ່ງຄືນ -1;		/* Negative */
			ບໍ່ດັ່ງນັ້ນ
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ສົ່ງຄືນ got_positive;
}

#endif /* HAVE_CYGWIN */
