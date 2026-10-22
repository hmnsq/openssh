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

#define NO_இருமம்_OPEN	/* Avoid redefining open to binary_open for this file */
#அந்தர்பாவ "includes.h"

#ifdef HAVE_CYGWIN

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <wchar.h>
#அந்தர்பாவ <wctype.h>

#அந்தர்பாவ "xmalloc.h"

முழு
இருமம்_open(மாறிலி எழுத்து *filename, முழு flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	திரும்பு (open(filename, flags | O_இருமம், mode));
}

முழு
check_ntsec(மாறிலி எழுத்து *filename)
{
	திரும்பு (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

மாறிலி எழுத்து *
cygwin_ssh_privsep_user()
{
  நிலையான எழுத்து cyg_privsep_user[DNLEN + UNLEN + 2];

  எனில் (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      எனில் (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   அளவு cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", அளவு(cyg_privsep_user));
    }
  திரும்பு cyg_privsep_user;
}

#define NL(x) x, (அளவு (x) - 1)
#define WENV_SIZ (அளவு (wenv_arr) / அளவு (wenv_arr[0]))

நிலையான கட்டமைப்பு wenv {
	மாறிலி எழுத்து *name;
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

எழுத்து **
fetch_windows_environment(வெறுமை)
{
	எழுத்து **e, **p;
	unsigned முழு i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, அளவு(எழுத்து *));
	க்கு (e = environ; *e != வெற்று; ++e) {
		க்கு (i = 0; i < WENV_SIZ; ++i) {
			எனில் (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = வெற்று;
	திரும்பு p;
}

வெறுமை
free_windows_environment(எழுத்து **p)
{
	விடுவி(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

நிலையான முழு
__match_pattern (மாறிலி wchar_t *s, மாறிலி wchar_t *pattern)
{
	க்கு (;;) {
		/* If at end of pattern, accept if also at end of string. */
		எனில் (!*pattern)
			திரும்பு !*s;

		எனில் (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			எனில் (!*pattern)
				திரும்பு 1;

			/* If next character in pattern is known, optimize. */
			எனில் (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				க்கு (; *s; s++)
					எனில் (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						திரும்பு 1;
				/* Failed. */
				திரும்பு 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			க்கு (; *s; s++)
				எனில் (__match_pattern(s, pattern))
					திரும்பு 1;
			/* Failed. */
			திரும்பு 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		எனில் (!*s)
			திரும்பு 0;

		/* Check if the next character of the string is acceptable. */
		எனில் (*pattern != '?' && towlower(*pattern) != towlower(*s))
			திரும்பு 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

நிலையான முழு
_match_pattern(மாறிலி எழுத்து *s, மாறிலி எழுத்து *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	முழு ret;

	எனில் ((len = mbstowcs(வெற்று, s, 0)) == (size_t) -1)
		திரும்பு 0;
	ws = (wchar_t *) xcalloc(len + 1, அளவு (wchar_t));
	mbstowcs(ws, s, len + 1);
	எனில் ((len = mbstowcs(வெற்று, pattern, 0)) == (size_t) -1) {
		விடுவி(ws);
		திரும்பு 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, அளவு (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	விடுவி(ws);
	விடுவி(wpattern);
	திரும்பு ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
முழு
cygwin_ug_match_pattern_list(மாறிலி எழுத்து *string, மாறிலி எழுத்து *pattern)
{
	எழுத்து sub[1024];
	முழு negated;
	முழு got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	க்கு (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		எனில் (pattern[i] == '!') {
			negated = 1;
			i++;
		} இல்லையெனில்
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		க்கு (subi = 0;
		    i < len && subi < அளவு(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		எனில் (subi >= அளவு(sub) - 1)
			திரும்பு 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		எனில் (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		எனில் (_match_pattern(string, sub)) {
			எனில் (negated)
				திரும்பு -1;		/* Negative */
			இல்லையெனில்
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	திரும்பு got_positive;
}

#endif /* HAVE_CYGWIN */
