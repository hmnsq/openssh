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

#నిర్వచించు NO_ద్విమాన_OPEN	/* Avoid redefining open to binary_open for this file */
#అన్తర్భావ "includes.h"

#నిర్వచితమైతే HAVE_CYGWIN

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <wchar.h>
#అన్తర్భావ <wctype.h>

#అన్తర్భావ "xmalloc.h"

పూర్ణాంకం
ద్విమాన_open(స్థిరరాశి అక్షరం *filename, పూర్ణాంకం flags, ...)
{
	va_list ap;
	బహుళకం_t బహుళకం;

	va_start(ap, flags);
	బహుళకం = va_arg(ap, బహుళకం_t);
	va_end(ap);
	తిరిగి (open(filename, flags | O_ద్విమాన, బహుళకం));
}

పూర్ణాంకం
check_ntsec(స్థిరరాశి అక్షరం *filename)
{
	తిరిగి (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

స్థిరరాశి అక్షరం *
cygwin_ssh_privsep_user()
{
  స్థిర అక్షరం cyg_privsep_user[DNLEN + UNLEN + 2];

  ఒకవేళ (!cyg_privsep_user[0])
    {
#నిర్వచితమైతే CW_CYGNAME_FROM_WINNAME
      ఒకవేళ (cygwin_అంతర్గత (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   పరిమాణం cyg_privsep_user) != 0)
#అయితే_ముగింపు
	strlcpy(cyg_privsep_user, "sshd", పరిమాణం(cyg_privsep_user));
    }
  తిరిగి cyg_privsep_user;
}

#నిర్వచించు NL(x) x, (పరిమాణం (x) - 1)
#నిర్వచించు WENV_SIZ (పరిమాణం (wenv_arr) / పరిమాణం (wenv_arr[0]))

స్థిర నిర్మాణం wenv {
	స్థిరరాశి అక్షరం *name;
	కొలత_t namelen;
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

అక్షరం **
fetch_windows_environment(శూన్య)
{
	అక్షరం **e, **p;
	గుర్తులేని పూర్ణాంకం i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, పరిమాణం(అక్షరం *));
	కొరకు (e = environ; *e != ఖాళీ; ++e) {
		కొరకు (i = 0; i < WENV_SIZ; ++i) {
			ఒకవేళ (!అక్షరశ్రేణి_పోలిక(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = ఖాళీ;
	తిరిగి p;
}

శూన్య
free_windows_environment(అక్షరం **p)
{
	విడుదల(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

స్థిర పూర్ణాంకం
__match_pattern (స్థిరరాశి wchar_t *s, స్థిరరాశి wchar_t *నమూనా)
{
	కొరకు (;;) {
		/* If at end of pattern, accept if also at end of string. */
		ఒకవేళ (!*నమూనా)
			తిరిగి !*s;

		ఒకవేళ (*నమూనా == '*') {
			/* Skip the asterisk. */
			నమూనా++;

			/* If at end of pattern, accept immediately. */
			ఒకవేళ (!*నమూనా)
				తిరిగి 1;

			/* If next character in pattern is known, optimize. */
			ఒకవేళ (*నమూనా != '?' && *నమూనా != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				కొరకు (; *s; s++)
					ఒకవేళ (*s == *నమూనా &&
					    __match_pattern(s + 1, నమూనా + 1))
						తిరిగి 1;
				/* Failed. */
				తిరిగి 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			కొరకు (; *s; s++)
				ఒకవేళ (__match_pattern(s, నమూనా))
					తిరిగి 1;
			/* Failed. */
			తిరిగి 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		ఒకవేళ (!*s)
			తిరిగి 0;

		/* Check if the next character of the string is acceptable. */
		ఒకవేళ (*నమూనా != '?' && towlower(*నమూనా) != towlower(*s))
			తిరిగి 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		నమూనా++;
	}
	/* NOTREACHED */
}

స్థిర పూర్ణాంకం
సరిపోలిక_నమూనా_2(స్థిరరాశి అక్షరం *s, స్థిరరాశి అక్షరం *నమూనా)
{
	wchar_t *ws;
	wchar_t *wpattern;
	కొలత_t len;
	పూర్ణాంకం ret;

	ఒకవేళ ((len = mbstowcs(ఖాళీ, s, 0)) == (కొలత_t) -1)
		తిరిగి 0;
	ws = (wchar_t *) xcalloc(len + 1, పరిమాణం (wchar_t));
	mbstowcs(ws, s, len + 1);
	ఒకవేళ ((len = mbstowcs(ఖాళీ, నమూనా, 0)) == (కొలత_t) -1) {
		విడుదల(ws);
		తిరిగి 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, పరిమాణం (wchar_t));
	mbstowcs(wpattern, నమూనా, len + 1);
	ret = __match_pattern (ws, wpattern);
	విడుదల(ws);
	విడుదల(wpattern);
	తిరిగి ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
పూర్ణాంకం
cygwin_ug_సరిపోలిక_నమూనా_list(స్థిరరాశి అక్షరం *string, స్థిరరాశి అక్షరం *నమూనా)
{
	అక్షరం sub[1024];
	పూర్ణాంకం negated;
	పూర్ణాంకం got_ధనాత్మక;
	కొలత_t i, subi, len = అక్షరశ్రేణి_పొడవు(నమూనా);

	got_ధనాత్మక = 0;
	కొరకు (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ఒకవేళ (నమూనా[i] == '!') {
			negated = 1;
			i++;
		} లేకపోతే
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		కొరకు (subi = 0;
		    i < len && subi < పరిమాణం(sub) - 1 && నమూనా[i] != ',';
		    subi++, i++)
			sub[subi] = నమూనా[i];
		/* If subpattern too long, return failure (no match). */
		ఒకవేళ (subi >= పరిమాణం(sub) - 1)
			తిరిగి 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ఒకవేళ (i < len && నమూనా[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ఒకవేళ (సరిపోలిక_నమూనా_2(string, sub)) {
			ఒకవేళ (negated)
				తిరిగి -1;		/* Negative */
			లేకపోతే
				got_ధనాత్మక = 1;	/*ధనాత్మక*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	తిరిగి got_ధనాత్మక;
}

#అయితే_ముగింపు /* HAVE_CYGWIN */
