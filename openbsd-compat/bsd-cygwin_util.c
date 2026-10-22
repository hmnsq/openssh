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

পূর্ণসংখ্যা
দ্বিমিক_open(ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	ফেরত (open(filename, flags | O_দ্বিমিক, mode));
}

পূর্ণসংখ্যা
check_ntsec(ধ্রুবক অক্ষর *filename)
{
	ফেরত (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ধ্রুবক অক্ষর *
cygwin_ssh_privsep_user()
{
  স্থির অক্ষর cyg_privsep_user[DNLEN + UNLEN + 2];

  যদি (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      যদি (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   আকার cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", আকার(cyg_privsep_user));
    }
  ফেরত cyg_privsep_user;
}

#define NL(x) x, (আকার (x) - 1)
#define WENV_SIZ (আকার (wenv_arr) / আকার (wenv_arr[0]))

স্থির কাঠামো wenv {
	ধ্রুবক অক্ষর *name;
	আকার_t namelen;
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

অক্ষর **
fetch_windows_environment(শূন্য)
{
	অক্ষর **e, **p;
	unsigned পূর্ণসংখ্যা i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, আকার(অক্ষর *));
	জন্য (e = environ; *e != ফাঁকা; ++e) {
		জন্য (i = 0; i < WENV_SIZ; ++i) {
			যদি (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = ফাঁকা;
	ফেরত p;
}

শূন্য
free_windows_environment(অক্ষর **p)
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

স্থির পূর্ণসংখ্যা
__match_pattern (ধ্রুবক wchar_t *s, ধ্রুবক wchar_t *pattern)
{
	জন্য (;;) {
		/* If at end of pattern, accept if also at end of string. */
		যদি (!*pattern)
			ফেরত !*s;

		যদি (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			যদি (!*pattern)
				ফেরত 1;

			/* If next character in pattern is known, optimize. */
			যদি (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				জন্য (; *s; s++)
					যদি (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						ফেরত 1;
				/* Failed. */
				ফেরত 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			জন্য (; *s; s++)
				যদি (__match_pattern(s, pattern))
					ফেরত 1;
			/* Failed. */
			ফেরত 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		যদি (!*s)
			ফেরত 0;

		/* Check if the next character of the string is acceptable. */
		যদি (*pattern != '?' && towlower(*pattern) != towlower(*s))
			ফেরত 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

স্থির পূর্ণসংখ্যা
_match_pattern(ধ্রুবক অক্ষর *s, ধ্রুবক অক্ষর *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	আকার_t len;
	পূর্ণসংখ্যা ret;

	যদি ((len = mbstowcs(ফাঁকা, s, 0)) == (আকার_t) -1)
		ফেরত 0;
	ws = (wchar_t *) xcalloc(len + 1, আকার (wchar_t));
	mbstowcs(ws, s, len + 1);
	যদি ((len = mbstowcs(ফাঁকা, pattern, 0)) == (আকার_t) -1) {
		মুক্ত(ws);
		ফেরত 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, আকার (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	মুক্ত(ws);
	মুক্ত(wpattern);
	ফেরত ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
পূর্ণসংখ্যা
cygwin_ug_match_pattern_list(ধ্রুবক অক্ষর *string, ধ্রুবক অক্ষর *pattern)
{
	অক্ষর sub[1024];
	পূর্ণসংখ্যা negated;
	পূর্ণসংখ্যা got_positive;
	আকার_t i, subi, len = strlen(pattern);

	got_positive = 0;
	জন্য (i = 0; i < len;) {
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
		জন্য (subi = 0;
		    i < len && subi < আকার(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		যদি (subi >= আকার(sub) - 1)
			ফেরত 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		যদি (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		যদি (_match_pattern(string, sub)) {
			যদি (negated)
				ফেরত -1;		/* Negative */
			অন্যথা
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ফেরত got_positive;
}

#endif /* HAVE_CYGWIN */
