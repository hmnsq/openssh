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

#define NO_દ્વિઅંકી_OPEN	/* Avoid redefining open to binary_open for this file */
#અન્તર્ભાવ "includes.h"

#ifdef HAVE_CYGWIN

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <wchar.h>
#અન્તર્ભાવ <wctype.h>

#અન્તર્ભાવ "xmalloc.h"

પૂર્ણાંક
દ્વિઅંકી_open(અચલ અક્ષર *filename, પૂર્ણાંક flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	પાછા (open(filename, flags | O_દ્વિઅંકી, mode));
}

પૂર્ણાંક
check_ntsec(અચલ અક્ષર *filename)
{
	પાછા (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

અચલ અક્ષર *
cygwin_ssh_privsep_user()
{
  સ્થિર અક્ષર cyg_privsep_user[DNLEN + UNLEN + 2];

  જો (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      જો (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   કદ cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", કદ(cyg_privsep_user));
    }
  પાછા cyg_privsep_user;
}

#define NL(x) x, (કદ (x) - 1)
#define WENV_SIZ (કદ (wenv_arr) / કદ (wenv_arr[0]))

સ્થિર સંરચના wenv {
	અચલ અક્ષર *name;
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

અક્ષર **
fetch_windows_environment(શૂન્ય)
{
	અક્ષર **e, **p;
	unsigned પૂર્ણાંક i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, કદ(અક્ષર *));
	માટે (e = environ; *e != ખાલી; ++e) {
		માટે (i = 0; i < WENV_SIZ; ++i) {
			જો (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = ખાલી;
	પાછા p;
}

શૂન્ય
free_windows_environment(અક્ષર **p)
{
	મુક્ત(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

સ્થિર પૂર્ણાંક
__match_pattern (અચલ wchar_t *s, અચલ wchar_t *pattern)
{
	માટે (;;) {
		/* If at end of pattern, accept if also at end of string. */
		જો (!*pattern)
			પાછા !*s;

		જો (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			જો (!*pattern)
				પાછા 1;

			/* If next character in pattern is known, optimize. */
			જો (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				માટે (; *s; s++)
					જો (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						પાછા 1;
				/* Failed. */
				પાછા 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			માટે (; *s; s++)
				જો (__match_pattern(s, pattern))
					પાછા 1;
			/* Failed. */
			પાછા 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		જો (!*s)
			પાછા 0;

		/* Check if the next character of the string is acceptable. */
		જો (*pattern != '?' && towlower(*pattern) != towlower(*s))
			પાછા 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

સ્થિર પૂર્ણાંક
_match_pattern(અચલ અક્ષર *s, અચલ અક્ષર *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	પૂર્ણાંક ret;

	જો ((len = mbstowcs(ખાલી, s, 0)) == (size_t) -1)
		પાછા 0;
	ws = (wchar_t *) xcalloc(len + 1, કદ (wchar_t));
	mbstowcs(ws, s, len + 1);
	જો ((len = mbstowcs(ખાલી, pattern, 0)) == (size_t) -1) {
		મુક્ત(ws);
		પાછા 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, કદ (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	મુક્ત(ws);
	મુક્ત(wpattern);
	પાછા ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
પૂર્ણાંક
cygwin_ug_match_pattern_list(અચલ અક્ષર *string, અચલ અક્ષર *pattern)
{
	અક્ષર sub[1024];
	પૂર્ણાંક negated;
	પૂર્ણાંક got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	માટે (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		જો (pattern[i] == '!') {
			negated = 1;
			i++;
		} નહીંતર
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		માટે (subi = 0;
		    i < len && subi < કદ(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		જો (subi >= કદ(sub) - 1)
			પાછા 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		જો (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		જો (_match_pattern(string, sub)) {
			જો (negated)
				પાછા -1;		/* Negative */
			નહીંતર
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	પાછા got_positive;
}

#endif /* HAVE_CYGWIN */
