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

#define NO_دودویی_OPEN	/* Avoid redefining open to binary_open for this file */
#شامل "includes.h"

#ifdef HAVE_CYGWIN

#شامل <sys/types.h>
#شامل <fcntl.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <wchar.h>
#شامل <wctype.h>

#شامل "xmalloc.h"

صحیح
دودویی_open(ثابت نویسه *filename, صحیح flags, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	بازگشت (open(filename, flags | O_دودویی, mode));
}

صحیح
check_ntsec(ثابت نویسه *filename)
{
	بازگشت (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ثابت نویسه *
cygwin_ssh_privsep_user()
{
  ایستا نویسه cyg_privsep_user[DNLEN + UNLEN + 2];

  اگر (!cyg_privsep_user[0])
    {
#ifdef CW_CYGNAME_FROM_WINNAME
      اگر (cygwin_internal (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   اندازه cyg_privsep_user) != 0)
#endif
	strlcpy(cyg_privsep_user, "sshd", اندازه(cyg_privsep_user));
    }
  بازگشت cyg_privsep_user;
}

#define NL(x) x, (اندازه (x) - 1)
#define WENV_SIZ (اندازه (wenv_arr) / اندازه (wenv_arr[0]))

ایستا ساختار wenv {
	ثابت نویسه *name;
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

نویسه **
fetch_windows_environment(تهی)
{
	نویسه **e, **p;
	unsigned صحیح i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, اندازه(نویسه *));
	برای (e = environ; *e != پوچ; ++e) {
		برای (i = 0; i < WENV_SIZ; ++i) {
			اگر (!strncmp(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = پوچ;
	بازگشت p;
}

تهی
free_windows_environment(نویسه **p)
{
	آزاد(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

ایستا صحیح
__match_pattern (ثابت wchar_t *s, ثابت wchar_t *pattern)
{
	برای (;;) {
		/* If at end of pattern, accept if also at end of string. */
		اگر (!*pattern)
			بازگشت !*s;

		اگر (*pattern == '*') {
			/* Skip the asterisk. */
			pattern++;

			/* If at end of pattern, accept immediately. */
			اگر (!*pattern)
				بازگشت 1;

			/* If next character in pattern is known, optimize. */
			اگر (*pattern != '?' && *pattern != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				برای (; *s; s++)
					اگر (*s == *pattern &&
					    __match_pattern(s + 1, pattern + 1))
						بازگشت 1;
				/* Failed. */
				بازگشت 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			برای (; *s; s++)
				اگر (__match_pattern(s, pattern))
					بازگشت 1;
			/* Failed. */
			بازگشت 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		اگر (!*s)
			بازگشت 0;

		/* Check if the next character of the string is acceptable. */
		اگر (*pattern != '?' && towlower(*pattern) != towlower(*s))
			بازگشت 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

ایستا صحیح
_match_pattern(ثابت نویسه *s, ثابت نویسه *pattern)
{
	wchar_t *ws;
	wchar_t *wpattern;
	size_t len;
	صحیح ret;

	اگر ((len = mbstowcs(پوچ, s, 0)) == (size_t) -1)
		بازگشت 0;
	ws = (wchar_t *) xcalloc(len + 1, اندازه (wchar_t));
	mbstowcs(ws, s, len + 1);
	اگر ((len = mbstowcs(پوچ, pattern, 0)) == (size_t) -1) {
		آزاد(ws);
		بازگشت 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, اندازه (wchar_t));
	mbstowcs(wpattern, pattern, len + 1);
	ret = __match_pattern (ws, wpattern);
	آزاد(ws);
	آزاد(wpattern);
	بازگشت ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
صحیح
cygwin_ug_match_pattern_list(ثابت نویسه *string, ثابت نویسه *pattern)
{
	نویسه sub[1024];
	صحیح negated;
	صحیح got_positive;
	size_t i, subi, len = strlen(pattern);

	got_positive = 0;
	برای (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		اگر (pattern[i] == '!') {
			negated = 1;
			i++;
		} وگرنه
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		برای (subi = 0;
		    i < len && subi < اندازه(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = pattern[i];
		/* If subpattern too long, return failure (no match). */
		اگر (subi >= اندازه(sub) - 1)
			بازگشت 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		اگر (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		اگر (_match_pattern(string, sub)) {
			اگر (negated)
				بازگشت -1;		/* Negative */
			وگرنه
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	بازگشت got_positive;
}

#endif /* HAVE_CYGWIN */
