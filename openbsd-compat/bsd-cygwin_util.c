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

#परिभाषय NO_द्विमान_OPEN	/* Avoid redefining open to binary_open for this file */
#अन्तर्भाव "includes.h"

#यदि_परिभाषितम् HAVE_CYGWIN

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <wchar.h>
#अन्तर्भाव <wctype.h>

#अन्तर्भाव "xmalloc.h"

पूर्णाङ्क
द्विमान_open(ध्रुव वर्ण *filename, पूर्णाङ्क flags, ...)
{
	va_list ap;
	बहुलकम्_t बहुलकम्;

	va_start(ap, flags);
	बहुलकम् = va_arg(ap, बहुलकम्_t);
	va_end(ap);
	प्रत्यागम (उद्घाटय(filename, flags | O_द्विमान, बहुलकम्));
}

पूर्णाङ्क
check_ntsec(ध्रुव वर्ण *filename)
{
	प्रत्यागम (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ध्रुव वर्ण *
cygwin_ssh_privsep_user()
{
  स्थिर वर्ण cyg_privsep_user[DNLEN + UNLEN + 2];

  यदि (!cyg_privsep_user[0])
    {
#यदि_परिभाषितम् CW_CYGNAME_FROM_WINNAME
      यदि (cygwin_आन्तरिकम् (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   परिमाण cyg_privsep_user) != 0)
#यदि_अन्तः
	strlcpy(cyg_privsep_user, "sshd", परिमाण(cyg_privsep_user));
    }
  प्रत्यागम cyg_privsep_user;
}

#परिभाषय NL(x) x, (परिमाण (x) - 1)
#परिभाषय WENV_SIZ (परिमाण (wenv_arr) / परिमाण (wenv_arr[0]))

स्थिर संरचना wenv {
	ध्रुव वर्ण *name;
	आकार_t namelen;
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

वर्ण **
fetch_windows_environment(शून्य)
{
	वर्ण **e, **p;
	अचिह्नित पूर्णाङ्क i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, परिमाण(वर्ण *));
	प्रति (e = environ; *e != रिक्त; ++e) {
		प्रति (i = 0; i < WENV_SIZ; ++i) {
			यदि (!वाक्ये_तुलय(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = रिक्त;
	प्रत्यागम p;
}

शून्य
free_windows_environment(वर्ण **p)
{
	मुक्त(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

स्थिर पूर्णाङ्क
__match_pattern (ध्रुव wchar_t *s, ध्रुव wchar_t *आदर्शः)
{
	प्रति (;;) {
		/* If at end of pattern, accept if also at end of string. */
		यदि (!*आदर्शः)
			प्रत्यागम !*s;

		यदि (*आदर्शः == '*') {
			/* Skip the asterisk. */
			आदर्शः++;

			/* If at end of pattern, accept immediately. */
			यदि (!*आदर्शः)
				प्रत्यागम 1;

			/* If next character in pattern is known, optimize. */
			यदि (*आदर्शः != '?' && *आदर्शः != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				प्रति (; *s; s++)
					यदि (*s == *आदर्शः &&
					    __match_pattern(s + 1, आदर्शः + 1))
						प्रत्यागम 1;
				/* Failed. */
				प्रत्यागम 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			प्रति (; *s; s++)
				यदि (__match_pattern(s, आदर्शः))
					प्रत्यागम 1;
			/* Failed. */
			प्रत्यागम 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		यदि (!*s)
			प्रत्यागम 0;

		/* Check if the next character of the string is acceptable. */
		यदि (*आदर्शः != '?' && towlower(*आदर्शः) != towlower(*s))
			प्रत्यागम 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		आदर्शः++;
	}
	/* NOTREACHED */
}

स्थिर पूर्णाङ्क
मेलनम्_आदर्शः_2(ध्रुव वर्ण *s, ध्रुव वर्ण *आदर्शः)
{
	wchar_t *ws;
	wchar_t *wpattern;
	आकार_t len;
	पूर्णाङ्क ret;

	यदि ((len = mbstowcs(रिक्त, s, 0)) == (आकार_t) -1)
		प्रत्यागम 0;
	ws = (wchar_t *) xcalloc(len + 1, परिमाण (wchar_t));
	mbstowcs(ws, s, len + 1);
	यदि ((len = mbstowcs(रिक्त, आदर्शः, 0)) == (आकार_t) -1) {
		मुक्त(ws);
		प्रत्यागम 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, परिमाण (wchar_t));
	mbstowcs(wpattern, आदर्शः, len + 1);
	ret = __match_pattern (ws, wpattern);
	मुक्त(ws);
	मुक्त(wpattern);
	प्रत्यागम ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
पूर्णाङ्क
cygwin_ug_मेलनम्_आदर्शः_list(ध्रुव वर्ण *string, ध्रुव वर्ण *आदर्शः)
{
	वर्ण sub[1024];
	पूर्णाङ्क negated;
	पूर्णाङ्क got_धनात्मकम्;
	आकार_t i, subi, len = वाक्यदैर्घ्यम्(आदर्शः);

	got_धनात्मकम् = 0;
	प्रति (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		यदि (आदर्शः[i] == '!') {
			negated = 1;
			i++;
		} अन्यथा
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		प्रति (subi = 0;
		    i < len && subi < परिमाण(sub) - 1 && आदर्शः[i] != ',';
		    subi++, i++)
			sub[subi] = आदर्शः[i];
		/* If subpattern too long, return failure (no match). */
		यदि (subi >= परिमाण(sub) - 1)
			प्रत्यागम 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		यदि (i < len && आदर्शः[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		यदि (मेलनम्_आदर्शः_2(string, sub)) {
			यदि (negated)
				प्रत्यागम -1;		/* Negative */
			अन्यथा
				got_धनात्मकम् = 1;	/*धनात्मकम्*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	प्रत्यागम got_धनात्मकम्;
}

#यदि_अन्तः /* HAVE_CYGWIN */
