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

#define NO_ದ್ವಿಮಾನ_OPEN	/* Avoid redefining open to binary_open for this file */
#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef HAVE_CYGWIN

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <wchar.h>
#ಅನ್ತರ್ಭಾವ <wctype.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"

ಪೂರ್ಣಾಙ್ಕ
ದ್ವಿಮಾನ_open(ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	ಪ್ರತ್ಯಾಗಮ (open(filename, flags | O_ದ್ವಿಮಾನ, mode));
}

ಪೂರ್ಣಾಙ್ಕ
check_ntsec(ಧ್ರುವ ವರ್ಣ *filename)
{
	ಪ್ರತ್ಯಾಗಮ (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ಧ್ರುವ ವರ್ಣ *
cygwin_ssh_privsep_user()
{
  ಸ್ಥಿರ ವರ್ಣ cyg_privsep_user[DNLEN + UNLEN + 2];

  ಯದಿ (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      ಯದಿ (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   ಪರಿಮಾಣ cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", ಪರಿಮಾಣ(cyg_privsep_user));
    }
  ಪ್ರತ್ಯಾಗಮ cyg_privsep_user;
}

#define NL(x) x, (ಪರಿಮಾಣ (x) - 1)
#define WENV_SIZ (ಪರಿಮಾಣ (wenv_arr) / ಪರಿಮಾಣ (wenv_arr[0]))

ಸ್ಥಿರ ಸಂರಚನಾ wenv {
	ಧ್ರುವ ವರ್ಣ *name;
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

ವರ್ಣ **
fetch_windows_environment(ಶೂನ್ಯ)
{
	ವರ್ಣ **e, **p;
	unsigned ಪೂರ್ಣಾಙ್ಕ i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, ಪರಿಮಾಣ(ವರ್ಣ *));
	ಪ್ರತಿ (e = environ; *e != ರಿಕ್ತ; ++e) {
		ಪ್ರತಿ (i = 0; i < WENV_SIZ; ++i) {
			ಯದಿ (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ p;
}

ಶೂನ್ಯ
free_windows_environment(ವರ್ಣ **p)
{
	ಮುಕ್ತ(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
__match_pattern (ಧ್ರುವ wchar_t *s, ಧ್ರುವ wchar_t *pattern)
{
	ಪ್ರತಿ (;;) {
		/* If at end of pattern, accept if also at end of string. */
		ಯದಿ (!*pattern)
			ಪ್ರತ್ಯಾಗಮ !*s;

		ಯದಿ (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			ಯದಿ (!*pattern)
				ಪ್ರತ್ಯಾಗಮ 1;

			/* If next character in pattern is known, optimize. */
			ಯದಿ (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				ಪ್ರತಿ (; *s; s++)
					ಯದಿ (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						ಪ್ರತ್ಯಾಗಮ 1;
				/* Failed. */
				ಪ್ರತ್ಯಾಗಮ 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			ಪ್ರತಿ (; *s; s++)
				ಯದಿ (__match_pattern(s, pattern))
					ಪ್ರತ್ಯಾಗಮ 1;
			/* Failed. */
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		ಯದಿ (!*s)
			ಪ್ರತ್ಯಾಗಮ 0;

		/* Check if the next character of the string is acceptable. */
		ಯದಿ (*pattern != '?' && towlower(*pattern) != towlower(*s))
			ಪ್ರತ್ಯಾಗಮ 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
_match_pattern(ಧ್ರುವ ವರ್ಣ *s, ಧ್ರುವ ವರ್ಣ *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ ret;

	ಯದಿ ((len = mbstowcs(ರಿಕ್ತ, s, 0)) == (size_t) -1)
		ಪ್ರತ್ಯಾಗಮ 0;
	ws = (wchar_t *) xcalloc(len + 1, ಪರಿಮಾಣ (wchar_t));
	mbstowcs(ws, s, len + 1);
	ಯದಿ ((len = mbstowcs(ರಿಕ್ತ, pattern, 0)) == (size_t) -1) {
		ಮುಕ್ತ(ws);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, ಪರಿಮಾಣ (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	ಮುಕ್ತ(ws);
	ಮುಕ್ತ(wpattern);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ಪೂರ್ಣಾಙ್ಕ
cygwin_ug_match_pattern_list(ಧ್ರುವ ವರ್ಣ *string, ಧ್ರುವ ವರ್ಣ *pattern)
{
	ವರ್ಣ sub[1024];
	ಪೂರ್ಣಾಙ್ಕ negated;
	ಪೂರ್ಣಾಙ್ಕ got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	ಪ್ರತಿ (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ಯದಿ (pattern[i] == '!') {
			negated = 1;
			i++;
		} ಅನ್ಯಥಾ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		ಪ್ರತಿ (subi = 0;
		    i < len && subi < ಪರಿಮಾಣ(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		ಯದಿ (subi >= ಪರಿಮಾಣ(sub) - 1)
			ಪ್ರತ್ಯಾಗಮ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ಯದಿ (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ಯದಿ (_match_pattern(string, sub)) {
			ಯದಿ (negated)
				ಪ್ರತ್ಯಾಗಮ -1;		/* Negative */
			ಅನ್ಯಥಾ
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ಪ್ರತ್ಯಾಗಮ got_positive;
}

#endif /* HAVE_CYGWIN */
