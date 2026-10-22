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

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NO_ਦੁਆਧਾਰੀ_OPEN	/* Avoid redefining open to binary_open for this file */
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <wchar.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <wctype.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

ਪੂਰਨ
ਦੁਆਧਾਰੀ_open(ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ flags, ...)
{
	va_list ap;
	ਬਹੁਲਕ_t ਬਹੁਲਕ;

	va_start(ap, flags);
	ਬਹੁਲਕ = va_arg(ap, ਬਹੁਲਕ_t);
	va_end(ap);
	ਵਾਪਸ (open(filename, flags | O_ਦੁਆਧਾਰੀ, ਬਹੁਲਕ));
}

ਪੂਰਨ
check_ntsec(ਅਚਲ ਅੱਖਰ *filename)
{
	ਵਾਪਸ (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ਅਚਲ ਅੱਖਰ *
cygwin_ssh_privsep_user()
{
  ਸਥਿਰ ਅੱਖਰ cyg_privsep_user[DNLEN + UNLEN + 2];

  ਜੇ (!cyg_privsep_user[0])
    {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ CW_CYGNAME_FROM_WINNAME
      ਜੇ (cygwin_ਅੰਦਰੂਨੀ (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   ਆਕਾਰ cyg_privsep_user) != 0)
#ਜੇ_ਅੰਤ
	strlcpy(cyg_privsep_user, "sshd", ਆਕਾਰ(cyg_privsep_user));
    }
  ਵਾਪਸ cyg_privsep_user;
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NL(x) x, (ਆਕਾਰ (x) - 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WENV_SIZ (ਆਕਾਰ (wenv_arr) / ਆਕਾਰ (wenv_arr[0]))

ਸਥਿਰ ਬਣਤਰ wenv {
	ਅਚਲ ਅੱਖਰ *name;
	ਮਾਪ_t namelen;
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

ਅੱਖਰ **
fetch_windows_environment(ਖਾਲੀ)
{
	ਅੱਖਰ **e, **p;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, ਆਕਾਰ(ਅੱਖਰ *));
	ਲਈ (e = environ; *e != ਨਿਰਾ; ++e) {
		ਲਈ (i = 0; i < WENV_SIZ; ++i) {
			ਜੇ (!ਲੜੀ_ਤੁਲਨਾ(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = ਨਿਰਾ;
	ਵਾਪਸ p;
}

ਖਾਲੀ
free_windows_environment(ਅੱਖਰ **p)
{
	ਮੁਕਤ(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

ਸਥਿਰ ਪੂਰਨ
__match_pattern (ਅਚਲ wchar_t *s, ਅਚਲ wchar_t *ਨਮੂਨਾ)
{
	ਲਈ (;;) {
		/* If at end of pattern, accept if also at end of string. */
		ਜੇ (!*ਨਮੂਨਾ)
			ਵਾਪਸ !*s;

		ਜੇ (*ਨਮੂਨਾ == '*') {
			/* Skip the asterisk. */
			ਨਮੂਨਾ++;

			/* If at end of pattern, accept immediately. */
			ਜੇ (!*ਨਮੂਨਾ)
				ਵਾਪਸ 1;

			/* If next character in pattern is known, optimize. */
			ਜੇ (*ਨਮੂਨਾ != '?' && *ਨਮੂਨਾ != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				ਲਈ (; *s; s++)
					ਜੇ (*s == *ਨਮੂਨਾ &&
					    __match_pattern(s + 1, ਨਮੂਨਾ + 1))
						ਵਾਪਸ 1;
				/* Failed. */
				ਵਾਪਸ 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			ਲਈ (; *s; s++)
				ਜੇ (__match_pattern(s, ਨਮੂਨਾ))
					ਵਾਪਸ 1;
			/* Failed. */
			ਵਾਪਸ 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		ਜੇ (!*s)
			ਵਾਪਸ 0;

		/* Check if the next character of the string is acceptable. */
		ਜੇ (*ਨਮੂਨਾ != '?' && towlower(*ਨਮੂਨਾ) != towlower(*s))
			ਵਾਪਸ 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		ਨਮੂਨਾ++;
	}
	/* NOTREACHED */
}

ਸਥਿਰ ਪੂਰਨ
ਮੇਲ_ਨਮੂਨਾ_2(ਅਚਲ ਅੱਖਰ *s, ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ)
{
	wchar_t *ws;
	wchar_t *wpattern;
	ਮਾਪ_t len;
	ਪੂਰਨ ret;

	ਜੇ ((len = mbstowcs(ਨਿਰਾ, s, 0)) == (ਮਾਪ_t) -1)
		ਵਾਪਸ 0;
	ws = (wchar_t *) xcalloc(len + 1, ਆਕਾਰ (wchar_t));
	mbstowcs(ws, s, len + 1);
	ਜੇ ((len = mbstowcs(ਨਿਰਾ, ਨਮੂਨਾ, 0)) == (ਮਾਪ_t) -1) {
		ਮੁਕਤ(ws);
		ਵਾਪਸ 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, ਆਕਾਰ (wchar_t));
	mbstowcs(wpattern, ਨਮੂਨਾ, len + 1);
	ret = __match_pattern (ws, wpattern);
	ਮੁਕਤ(ws);
	ਮੁਕਤ(wpattern);
	ਵਾਪਸ ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ਪੂਰਨ
cygwin_ug_ਮੇਲ_ਨਮੂਨਾ_list(ਅਚਲ ਅੱਖਰ *string, ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ)
{
	ਅੱਖਰ sub[1024];
	ਪੂਰਨ negated;
	ਪੂਰਨ got_ਸਕਾਰਾਤਮਕ;
	ਮਾਪ_t i, subi, len = ਲੜੀ_ਲੰਬਾਈ(ਨਮੂਨਾ);

	got_ਸਕਾਰਾਤਮਕ = 0;
	ਲਈ (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ਜੇ (ਨਮੂਨਾ[i] == '!') {
			negated = 1;
			i++;
		} ਨਹੀਂਤਾਂ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		ਲਈ (subi = 0;
		    i < len && subi < ਆਕਾਰ(sub) - 1 && ਨਮੂਨਾ[i] != ',';
		    subi++, i++)
			sub[subi] = ਨਮੂਨਾ[i];
		/* If subpattern too long, return failure (no match). */
		ਜੇ (subi >= ਆਕਾਰ(sub) - 1)
			ਵਾਪਸ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ਜੇ (i < len && ਨਮੂਨਾ[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ_2(string, sub)) {
			ਜੇ (negated)
				ਵਾਪਸ -1;		/* Negative */
			ਨਹੀਂਤਾਂ
				got_ਸਕਾਰਾਤਮਕ = 1;	/*ਸਕਾਰਾਤਮਕ*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ਵਾਪਸ got_ਸਕਾਰਾਤਮਕ;
}

#ਜੇ_ਅੰਤ /* HAVE_CYGWIN */
