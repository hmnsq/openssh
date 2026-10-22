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

#define NO_ദ്വിമാന_OPEN	/* Avoid redefining open to binary_open for this file */
#അന്തര്ഭാവ "includes.h"

#ifdef HAVE_CYGWIN

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <wchar.h>
#അന്തര്ഭാവ <wctype.h>

#അന്തര്ഭാവ "xmalloc.h"

പൂർണ്ണസംഖ്യ
ദ്വിമാന_open(സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	തിരികെ (open(filename, flags | O_ദ്വിമാന, mode));
}

പൂർണ്ണസംഖ്യ
check_ntsec(സ്ഥിരം അക്ഷരം *filename)
{
	തിരികെ (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

സ്ഥിരം അക്ഷരം *
cygwin_ssh_privsep_user()
{
  സ്ഥിതം അക്ഷരം cyg_privsep_user[DNLEN + UNLEN + 2];

  എങ്കിൽ (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      എങ്കിൽ (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   വലുപ്പം cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", വലുപ്പം(cyg_privsep_user));
    }
  തിരികെ cyg_privsep_user;
}

#define NL(x) x, (വലുപ്പം (x) - 1)
#define WENV_SIZ (വലുപ്പം (wenv_arr) / വലുപ്പം (wenv_arr[0]))

സ്ഥിതം ഘടന wenv {
	സ്ഥിരം അക്ഷരം *name;
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

അക്ഷരം **
fetch_windows_environment(ശൂന്യം)
{
	അക്ഷരം **e, **p;
	unsigned പൂർണ്ണസംഖ്യ i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, വലുപ്പം(അക്ഷരം *));
	വേണ്ടി (e = environ; *e != ശൂന്യ; ++e) {
		വേണ്ടി (i = 0; i < WENV_SIZ; ++i) {
			എങ്കിൽ (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = ശൂന്യ;
	തിരികെ p;
}

ശൂന്യം
free_windows_environment(അക്ഷരം **p)
{
	സ്വതന്ത്രം(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

സ്ഥിതം പൂർണ്ണസംഖ്യ
__match_pattern (സ്ഥിരം wchar_t *s, സ്ഥിരം wchar_t *pattern)
{
	വേണ്ടി (;;) {
		/* If at end of pattern, accept if also at end of string. */
		എങ്കിൽ (!*pattern)
			തിരികെ !*s;

		എങ്കിൽ (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			എങ്കിൽ (!*pattern)
				തിരികെ 1;

			/* If next character in pattern is known, optimize. */
			എങ്കിൽ (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				വേണ്ടി (; *s; s++)
					എങ്കിൽ (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						തിരികെ 1;
				/* Failed. */
				തിരികെ 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			വേണ്ടി (; *s; s++)
				എങ്കിൽ (__match_pattern(s, pattern))
					തിരികെ 1;
			/* Failed. */
			തിരികെ 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		എങ്കിൽ (!*s)
			തിരികെ 0;

		/* Check if the next character of the string is acceptable. */
		എങ്കിൽ (*pattern != '?' && towlower(*pattern) != towlower(*s))
			തിരികെ 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
_match_pattern(സ്ഥിരം അക്ഷരം *s, സ്ഥിരം അക്ഷരം *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	പൂർണ്ണസംഖ്യ ret;

	എങ്കിൽ ((len = mbstowcs(ശൂന്യ, s, 0)) == (size_t) -1)
		തിരികെ 0;
	ws = (wchar_t *) xcalloc(len + 1, വലുപ്പം (wchar_t));
	mbstowcs(ws, s, len + 1);
	എങ്കിൽ ((len = mbstowcs(ശൂന്യ, pattern, 0)) == (size_t) -1) {
		സ്വതന്ത്രം(ws);
		തിരികെ 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, വലുപ്പം (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	സ്വതന്ത്രം(ws);
	സ്വതന്ത്രം(wpattern);
	തിരികെ ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
പൂർണ്ണസംഖ്യ
cygwin_ug_match_pattern_list(സ്ഥിരം അക്ഷരം *string, സ്ഥിരം അക്ഷരം *pattern)
{
	അക്ഷരം sub[1024];
	പൂർണ്ണസംഖ്യ negated;
	പൂർണ്ണസംഖ്യ got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	വേണ്ടി (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		എങ്കിൽ (pattern[i] == '!') {
			negated = 1;
			i++;
		} അല്ലെങ്കിൽ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		വേണ്ടി (subi = 0;
		    i < len && subi < വലുപ്പം(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		എങ്കിൽ (subi >= വലുപ്പം(sub) - 1)
			തിരികെ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		എങ്കിൽ (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		എങ്കിൽ (_match_pattern(string, sub)) {
			എങ്കിൽ (negated)
				തിരികെ -1;		/* Negative */
			അല്ലെങ്കിൽ
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	തിരികെ got_positive;
}

#endif /* HAVE_CYGWIN */
