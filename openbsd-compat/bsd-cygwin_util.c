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

#تعریف_کرو NO_ثنائی_OPEN	/* Avoid redefining open to binary_open for this file */
#شامل "includes.h"

#اگر_تعریف_شدہ HAVE_CYGWIN

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
ثنائی_open(ثابت حرف *filename, صحیح flags, ...)
{
	va_list ap;
	منوال_t منوال;

	va_start(ap, flags);
	منوال = va_arg(ap, منوال_t);
	va_end(ap);
	واپس (open(filename, flags | O_ثنائی, منوال));
}

صحیح
check_ntsec(ثابت حرف *filename)
{
	واپس (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ثابت حرف *
cygwin_ssh_privsep_user()
{
  ساکن حرف cyg_privsep_user[DNLEN + UNLEN + 2];

  اگر (!cyg_privsep_user[0])
    {
#اگر_تعریف_شدہ CW_CYGNAME_FROM_WINNAME
      اگر (cygwin_اندرونی (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   حجم cyg_privsep_user) != 0)
#اگر_ختم
	strlcpy(cyg_privsep_user, "sshd", حجم(cyg_privsep_user));
    }
  واپس cyg_privsep_user;
}

#تعریف_کرو NL(x) x, (حجم (x) - 1)
#تعریف_کرو WENV_SIZ (حجم (wenv_arr) / حجم (wenv_arr[0]))

ساکن ساخت wenv {
	ثابت حرف *name;
	سائز_t namelen;
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

حرف **
fetch_windows_environment(خالی)
{
	حرف **e, **p;
	غیرعلامتی صحیح i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, حجم(حرف *));
	برائے (e = environ; *e != تہی; ++e) {
		برائے (i = 0; i < WENV_SIZ; ++i) {
			اگر (!لڑی_موازنہ(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = تہی;
	واپس p;
}

خالی
free_windows_environment(حرف **p)
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

ساکن صحیح
__match_pattern (ثابت wchar_t *s, ثابت wchar_t *نمونہ)
{
	برائے (;;) {
		/* If at end of pattern, accept if also at end of string. */
		اگر (!*نمونہ)
			واپس !*s;

		اگر (*نمونہ == '*') {
			/* Skip the asterisk. */
			نمونہ++;

			/* If at end of pattern, accept immediately. */
			اگر (!*نمونہ)
				واپس 1;

			/* If next character in pattern is known, optimize. */
			اگر (*نمونہ != '?' && *نمونہ != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				برائے (; *s; s++)
					اگر (*s == *نمونہ &&
					    __match_pattern(s + 1, نمونہ + 1))
						واپس 1;
				/* Failed. */
				واپس 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			برائے (; *s; s++)
				اگر (__match_pattern(s, نمونہ))
					واپس 1;
			/* Failed. */
			واپس 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		اگر (!*s)
			واپس 0;

		/* Check if the next character of the string is acceptable. */
		اگر (*نمونہ != '?' && towlower(*نمونہ) != towlower(*s))
			واپس 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		نمونہ++;
	}
	/* NOTREACHED */
}

ساکن صحیح
مطابقت_نمونہ_2(ثابت حرف *s, ثابت حرف *نمونہ)
{
	wchar_t *ws;
	wchar_t *wpattern;
	سائز_t len;
	صحیح ret;

	اگر ((len = mbstowcs(تہی, s, 0)) == (سائز_t) -1)
		واپس 0;
	ws = (wchar_t *) xcalloc(len + 1, حجم (wchar_t));
	mbstowcs(ws, s, len + 1);
	اگر ((len = mbstowcs(تہی, نمونہ, 0)) == (سائز_t) -1) {
		آزاد(ws);
		واپس 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, حجم (wchar_t));
	mbstowcs(wpattern, نمونہ, len + 1);
	ret = __match_pattern (ws, wpattern);
	آزاد(ws);
	آزاد(wpattern);
	واپس ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
صحیح
cygwin_ug_مطابقت_نمونہ_list(ثابت حرف *string, ثابت حرف *نمونہ)
{
	حرف sub[1024];
	صحیح negated;
	صحیح got_مثبت;
	سائز_t i, subi, len = لڑی_لمبائی(نمونہ);

	got_مثبت = 0;
	برائے (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		اگر (نمونہ[i] == '!') {
			negated = 1;
			i++;
		} ورنہ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		برائے (subi = 0;
		    i < len && subi < حجم(sub) - 1 && نمونہ[i] != ',';
		    subi++, i++)
			sub[subi] = نمونہ[i];
		/* If subpattern too long, return failure (no match). */
		اگر (subi >= حجم(sub) - 1)
			واپس 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		اگر (i < len && نمونہ[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		اگر (مطابقت_نمونہ_2(string, sub)) {
			اگر (negated)
				واپس -1;		/* Negative */
			ورنہ
				got_مثبت = 1;	/*مثبت*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	واپس got_مثبت;
}

#اگر_ختم /* HAVE_CYGWIN */
