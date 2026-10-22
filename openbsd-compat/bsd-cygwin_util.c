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

#ವ್ಯಾಖ್ಯಾನಿಸು NO_ದ್ವಿಮಾನ_OPEN	/* Avoid redefining open to binary_open for this file */
#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <wchar.h>
#ಅನ್ತರ್ಭಾವ <wctype.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"

ಪೂರ್ಣಾಂಕ
ದ್ವಿಮಾನ_open(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ flags, ...)
{
	va_list ap;
	ಬಹುಲಕ_t ಬಹುಲಕ;

	va_start(ap, flags);
	ಬಹುಲಕ = va_arg(ap, ಬಹುಲಕ_t);
	va_end(ap);
	ಹಿಂತಿರುಗಿ (open(filename, flags | O_ದ್ವಿಮಾನ, ಬಹುಲಕ));
}

ಪೂರ್ಣಾಂಕ
check_ntsec(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename)
{
	ಹಿಂತಿರುಗಿ (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
cygwin_ssh_privsep_user()
{
  ಸ್ಥಿರ ಅಕ್ಷರ cyg_privsep_user[DNLEN + UNLEN + 2];

  ಆದರೆ (!cyg_privsep_user[0])
    {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ CW_CYGNAME_FROM_WINNAME
      ಆದರೆ (cygwin_ಆಂತರಿಕ (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   ಗಾತ್ರ cyg_privsep_user) != 0)
#ಆದರೆ_ಅಂತ್ಯ
	strlcpy(cyg_privsep_user, "sshd", ಗಾತ್ರ(cyg_privsep_user));
    }
  ಹಿಂತಿರುಗಿ cyg_privsep_user;
}

#ವ್ಯಾಖ್ಯಾನಿಸು NL(x) x, (ಗಾತ್ರ (x) - 1)
#ವ್ಯಾಖ್ಯಾನಿಸು WENV_SIZ (ಗಾತ್ರ (wenv_arr) / ಗಾತ್ರ (wenv_arr[0]))

ಸ್ಥಿರ ರಚನೆ wenv {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	ಗಾತ್ರ_t namelen;
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

ಅಕ್ಷರ **
fetch_windows_environment(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ **e, **p;
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, ಗಾತ್ರ(ಅಕ್ಷರ *));
	ಗಾಗಿ (e = environ; *e != ಖಾಲಿ; ++e) {
		ಗಾಗಿ (i = 0; i < WENV_SIZ; ++i) {
			ಆದರೆ (!ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ p;
}

ಶೂನ್ಯ
free_windows_environment(ಅಕ್ಷರ **p)
{
	ಬಿಡುಗಡೆ(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
__match_pattern (ಸ್ಥಿರಾಂಕ wchar_t *s, ಸ್ಥಿರಾಂಕ wchar_t *ನಮೂನೆ)
{
	ಗಾಗಿ (;;) {
		/* If at end of pattern, accept if also at end of string. */
		ಆದರೆ (!*ನಮೂನೆ)
			ಹಿಂತಿರುಗಿ !*s;

		ಆದರೆ (*ನಮೂನೆ == '*') {
			/* Skip the asterisk. */
			ನಮೂನೆ++;

			/* If at end of pattern, accept immediately. */
			ಆದರೆ (!*ನಮೂನೆ)
				ಹಿಂತಿರುಗಿ 1;

			/* If next character in pattern is known, optimize. */
			ಆದರೆ (*ನಮೂನೆ != '?' && *ನಮೂನೆ != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				ಗಾಗಿ (; *s; s++)
					ಆದರೆ (*s == *ನಮೂನೆ &&
					    __match_pattern(s + 1, ನಮೂನೆ + 1))
						ಹಿಂತಿರುಗಿ 1;
				/* Failed. */
				ಹಿಂತಿರುಗಿ 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			ಗಾಗಿ (; *s; s++)
				ಆದರೆ (__match_pattern(s, ನಮೂನೆ))
					ಹಿಂತಿರುಗಿ 1;
			/* Failed. */
			ಹಿಂತಿರುಗಿ 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		ಆದರೆ (!*s)
			ಹಿಂತಿರುಗಿ 0;

		/* Check if the next character of the string is acceptable. */
		ಆದರೆ (*ನಮೂನೆ != '?' && towlower(*ನಮೂನೆ) != towlower(*s))
			ಹಿಂತಿರುಗಿ 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		ನಮೂನೆ++;
	}
	/* NOTREACHED */
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_ನಮೂನೆ_2(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ)
{
	wchar_t *ws;
	wchar_t *wpattern;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ ret;

	ಆದರೆ ((len = mbstowcs(ಖಾಲಿ, s, 0)) == (ಗಾತ್ರ_t) -1)
		ಹಿಂತಿರುಗಿ 0;
	ws = (wchar_t *) xcalloc(len + 1, ಗಾತ್ರ (wchar_t));
	mbstowcs(ws, s, len + 1);
	ಆದರೆ ((len = mbstowcs(ಖಾಲಿ, ನಮೂನೆ, 0)) == (ಗಾತ್ರ_t) -1) {
		ಬಿಡುಗಡೆ(ws);
		ಹಿಂತಿರುಗಿ 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, ಗಾತ್ರ (wchar_t));
	mbstowcs(wpattern, ನಮೂನೆ, len + 1);
	ret = __match_pattern (ws, wpattern);
	ಬಿಡುಗಡೆ(ws);
	ಬಿಡುಗಡೆ(wpattern);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ಪೂರ್ಣಾಂಕ
cygwin_ug_ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *string, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ)
{
	ಅಕ್ಷರ sub[1024];
	ಪೂರ್ಣಾಂಕ negated;
	ಪೂರ್ಣಾಂಕ got_ಧನಾತ್ಮಕ;
	ಗಾತ್ರ_t i, subi, len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ನಮೂನೆ);

	got_ಧನಾತ್ಮಕ = 0;
	ಗಾಗಿ (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ಆದರೆ (ನಮೂನೆ[i] == '!') {
			negated = 1;
			i++;
		} ಇಲ್ಲದಿದ್ದರೆ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		ಗಾಗಿ (subi = 0;
		    i < len && subi < ಗಾತ್ರ(sub) - 1 && ನಮೂನೆ[i] != ',';
		    subi++, i++)
			sub[subi] = ನಮೂನೆ[i];
		/* If subpattern too long, return failure (no match). */
		ಆದರೆ (subi >= ಗಾತ್ರ(sub) - 1)
			ಹಿಂತಿರುಗಿ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ಆದರೆ (i < len && ನಮೂನೆ[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_2(string, sub)) {
			ಆದರೆ (negated)
				ಹಿಂತಿರುಗಿ -1;		/* Negative */
			ಇಲ್ಲದಿದ್ದರೆ
				got_ಧನಾತ್ಮಕ = 1;	/*ಧನಾತ್ಮಕ*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ಹಿಂತಿರುಗಿ got_ಧನಾತ್ಮಕ;
}

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_CYGWIN */
