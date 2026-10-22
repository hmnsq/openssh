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

#define NO_ଦ୍ୱିମିକ_OPEN	/* Avoid redefining open to binary_open for this file */
#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef HAVE_CYGWIN

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <wchar.h>
#ଅନ୍ତର୍ଭାଵ <wctype.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଦ୍ୱିମିକ_open(ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	ଫେରନ୍ତୁ (open(filename, flags | O_ଦ୍ୱିମିକ, mode));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_ntsec(ଅଚଳ ଅକ୍ଷର *filename)
{
	ଫେରନ୍ତୁ (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ଅଚଳ ଅକ୍ଷର *
cygwin_ssh_privsep_user()
{
  ସ୍ଥିର ଅକ୍ଷର cyg_privsep_user[DNLEN + UNLEN + 2];

  ଯଦି (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      ଯଦି (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   ଆକାର cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", ଆକାର(cyg_privsep_user));
    }
  ଫେରନ୍ତୁ cyg_privsep_user;
}

#define NL(x) x, (ଆକାର (x) - 1)
#define WENV_SIZ (ଆକାର (wenv_arr) / ଆକାର (wenv_arr[0]))

ସ୍ଥିର ସଂରଚନା wenv {
	ଅଚଳ ଅକ୍ଷର *name;
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

ଅକ୍ଷର **
fetch_windows_environment(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର **e, **p;
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, ଆକାର(ଅକ୍ଷର *));
	ପାଇଁ (e = environ; *e != ଖାଲି; ++e) {
		ପାଇଁ (i = 0; i < WENV_SIZ; ++i) {
			ଯଦି (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = ଖାଲି;
	ଫେରନ୍ତୁ p;
}

ଶୂନ୍ୟ
free_windows_environment(ଅକ୍ଷର **p)
{
	ମୁକ୍ତ(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__match_pattern (ଅଚଳ wchar_t *s, ଅଚଳ wchar_t *pattern)
{
	ପାଇଁ (;;) {
		/* If at end of pattern, accept if also at end of string. */
		ଯଦି (!*pattern)
			ଫେରନ୍ତୁ !*s;

		ଯଦି (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			ଯଦି (!*pattern)
				ଫେରନ୍ତୁ 1;

			/* If next character in pattern is known, optimize. */
			ଯଦି (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				ପାଇଁ (; *s; s++)
					ଯଦି (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						ଫେରନ୍ତୁ 1;
				/* Failed. */
				ଫେରନ୍ତୁ 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			ପାଇଁ (; *s; s++)
				ଯଦି (__match_pattern(s, pattern))
					ଫେରନ୍ତୁ 1;
			/* Failed. */
			ଫେରନ୍ତୁ 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		ଯଦି (!*s)
			ଫେରନ୍ତୁ 0;

		/* Check if the next character of the string is acceptable. */
		ଯଦି (*pattern != '?' && towlower(*pattern) != towlower(*s))
			ଫେରନ୍ତୁ 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
_match_pattern(ଅଚଳ ଅକ୍ଷର *s, ଅଚଳ ଅକ୍ଷର *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	ଯଦି ((len = mbstowcs(ଖାଲି, s, 0)) == (size_t) -1)
		ଫେରନ୍ତୁ 0;
	ws = (wchar_t *) xcalloc(len + 1, ଆକାର (wchar_t));
	mbstowcs(ws, s, len + 1);
	ଯଦି ((len = mbstowcs(ଖାଲି, pattern, 0)) == (size_t) -1) {
		ମୁକ୍ତ(ws);
		ଫେରନ୍ତୁ 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, ଆକାର (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	ମୁକ୍ତ(ws);
	ମୁକ୍ତ(wpattern);
	ଫେରନ୍ତୁ ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cygwin_ug_match_pattern_list(ଅଚଳ ଅକ୍ଷର *string, ଅଚଳ ଅକ୍ଷର *pattern)
{
	ଅକ୍ଷର sub[1024];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା negated;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	ପାଇଁ (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ଯଦି (pattern[i] == '!') {
			negated = 1;
			i++;
		} ଅନ୍ୟଥା
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		ପାଇଁ (subi = 0;
		    i < len && subi < ଆକାର(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		ଯଦି (subi >= ଆକାର(sub) - 1)
			ଫେରନ୍ତୁ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ଯଦି (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ଯଦି (_match_pattern(string, sub)) {
			ଯଦି (negated)
				ଫେରନ୍ତୁ -1;		/* Negative */
			ଅନ୍ୟଥା
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ଫେରନ୍ତୁ got_positive;
}

#endif /* HAVE_CYGWIN */
