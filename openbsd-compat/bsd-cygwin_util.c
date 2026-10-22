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

#define NO_দ্বিমিক_OPEN	/* Avoid redefining open to binary_open for this file */
#অন্তর্ভাব "includes.h"

#ifdef HAVE_CYGWIN

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <wchar.h>
#অন্তর্ভাব <wctype.h>

#অন্তর্ভাব "xmalloc.h"

পূর্ণাঙ্ক
দ্বিমিক_open(ধ্রুব বর্ণ *filename, পূর্ণাঙ্ক flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	প্রত্যাগম (open(filename, flags | O_দ্বিমিক, mode));
}

পূর্ণাঙ্ক
check_ntsec(ধ্রুব বর্ণ *filename)
{
	প্রত্যাগম (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ধ্রুব বর্ণ *
cygwin_ssh_privsep_user()
{
  স্থির বর্ণ cyg_privsep_user[DNLEN + UNLEN + 2];

  যদি (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      যদি (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   পরিমাণ cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", পরিমাণ(cyg_privsep_user));
    }
  প্রত্যাগম cyg_privsep_user;
}

#define NL(x) x, (পরিমাণ (x) - 1)
#define WENV_SIZ (পরিমাণ (wenv_arr) / পরিমাণ (wenv_arr[0]))

স্থির সংরচনা wenv {
	ধ্রুব বর্ণ *name;
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

বর্ণ **
fetch_windows_environment(শূন্য)
{
	বর্ণ **e, **p;
	unsigned পূর্ণাঙ্ক i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, পরিমাণ(বর্ণ *));
	প্রতি (e = environ; *e != রিক্ত; ++e) {
		প্রতি (i = 0; i < WENV_SIZ; ++i) {
			যদি (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = রিক্ত;
	প্রত্যাগম p;
}

শূন্য
free_windows_environment(বর্ণ **p)
{
	মুক্ত(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

স্থির পূর্ণাঙ্ক
__match_pattern (ধ্রুব wchar_t *s, ধ্রুব wchar_t *pattern)
{
	প্রতি (;;) {
		/* If at end of pattern, accept if also at end of string. */
		যদি (!*pattern)
			প্রত্যাগম !*s;

		যদি (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			যদি (!*pattern)
				প্রত্যাগম 1;

			/* If next character in pattern is known, optimize. */
			যদি (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				প্রতি (; *s; s++)
					যদি (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						প্রত্যাগম 1;
				/* Failed. */
				প্রত্যাগম 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			প্রতি (; *s; s++)
				যদি (__match_pattern(s, pattern))
					প্রত্যাগম 1;
			/* Failed. */
			প্রত্যাগম 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		যদি (!*s)
			প্রত্যাগম 0;

		/* Check if the next character of the string is acceptable. */
		যদি (*pattern != '?' && towlower(*pattern) != towlower(*s))
			প্রত্যাগম 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

স্থির পূর্ণাঙ্ক
_match_pattern(ধ্রুব বর্ণ *s, ধ্রুব বর্ণ *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	পূর্ণাঙ্ক ret;

	যদি ((len = mbstowcs(রিক্ত, s, 0)) == (size_t) -1)
		প্রত্যাগম 0;
	ws = (wchar_t *) xcalloc(len + 1, পরিমাণ (wchar_t));
	mbstowcs(ws, s, len + 1);
	যদি ((len = mbstowcs(রিক্ত, pattern, 0)) == (size_t) -1) {
		মুক্ত(ws);
		প্রত্যাগম 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, পরিমাণ (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	মুক্ত(ws);
	মুক্ত(wpattern);
	প্রত্যাগম ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
পূর্ণাঙ্ক
cygwin_ug_match_pattern_list(ধ্রুব বর্ণ *string, ধ্রুব বর্ণ *pattern)
{
	বর্ণ sub[1024];
	পূর্ণাঙ্ক negated;
	পূর্ণাঙ্ক got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	প্রতি (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		যদি (pattern[i] == '!') {
			negated = 1;
			i++;
		} অন্যথা
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		প্রতি (subi = 0;
		    i < len && subi < পরিমাণ(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		যদি (subi >= পরিমাণ(sub) - 1)
			প্রত্যাগম 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		যদি (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		যদি (_match_pattern(string, sub)) {
			যদি (negated)
				প্রত্যাগম -1;		/* Negative */
			অন্যথা
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	প্রত্যাগম got_positive;
}

#endif /* HAVE_CYGWIN */
