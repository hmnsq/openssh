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
#ضمن "includes.h"

#جے_تعریف_شدہ HAVE_CYGWIN

#ضمن <sys/types.h>
#ضمن <fcntl.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <wchar.h>
#ضمن <wctype.h>

#ضمن "xmalloc.h"

صحيح
ثنائی_open(ثابت حرف *filename, صحيح flags, ...)
{
	va_list ap;
	منوال_t منوال;

	va_start(ap, flags);
	منوال = va_arg(ap, منوال_t);
	va_end(ap);
	أرجع (open(filename, flags | O_ثنائی, منوال));
}

صحيح
check_ntsec(ثابت حرف *filename)
{
	أرجع (pathconf(filename, _PC_POSIX_PERMISSIONS));
}

ثابت حرف *
cygwin_ssh_privsep_user()
{
  ساكن حرف cyg_privsep_user[DNLEN + UNLEN + 2];

  إذا (!cyg_privsep_user[0])
    {
#جے_تعریف_شدہ CW_CYGNAME_FROM_WINNAME
      إذا (cygwin_اندرونی (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   حجم cyg_privsep_user) != 0)
#جے_انت
	strlcpy(cyg_privsep_user, "sshd", حجم(cyg_privsep_user));
    }
  أرجع cyg_privsep_user;
}

#تعریف_کرو NL(x) x, (حجم (x) - 1)
#تعریف_کرو WENV_SIZ (حجم (wenv_arr) / حجم (wenv_arr[0]))

ساكن بنية wenv {
	ثابت حرف *name;
	ناپ_t namelen;
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
fetch_windows_environment(فراغ)
{
	حرف **e, **p;
	بنانشانی صحيح i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, حجم(حرف *));
	لكل (e = environ; *e != عدم; ++e) {
		لكل (i = 0; i < WENV_SIZ; ++i) {
			إذا (!لڑی_مقابلہ(*e, wenv_arr[i].name, wenv_arr[i].namelen))
				p[idx++] = *e;
		}
	}
	p[idx] = عدم;
	أرجع p;
}

فراغ
free_windows_environment(حرف **p)
{
	حرر(p);
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match.
 *
 * The Cygwin version of this function must be case-insensitive and take
 * Unicode characters into account.
 */

ساكن صحيح
__match_pattern (ثابت wchar_t *s, ثابت wchar_t *نمونہ)
{
	لكل (;;) {
		/* If at end of pattern, accept if also at end of string. */
		إذا (!*نمونہ)
			أرجع !*s;

		إذا (*نمونہ == '*') {
			/* Skip the asterisk. */
			نمونہ++;

			/* If at end of pattern, accept immediately. */
			إذا (!*نمونہ)
				أرجع 1;

			/* If next character in pattern is known, optimize. */
			إذا (*نمونہ != '?' && *نمونہ != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				لكل (; *s; s++)
					إذا (*s == *نمونہ &&
					    __match_pattern(s + 1, نمونہ + 1))
						أرجع 1;
				/* Failed. */
				أرجع 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			لكل (; *s; s++)
				إذا (__match_pattern(s, نمونہ))
					أرجع 1;
			/* Failed. */
			أرجع 0;
		}
		/*
		 * There must be at least one more character in the string.
		 * If we are at the end, fail.
		 */
		إذا (!*s)
			أرجع 0;

		/* Check if the next character of the string is acceptable. */
		إذا (*نمونہ != '?' && towlower(*نمونہ) != towlower(*s))
			أرجع 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		نمونہ++;
	}
	/* NOTREACHED */
}

ساكن صحيح
میل_نمونہ_2(ثابت حرف *s, ثابت حرف *نمونہ)
{
	wchar_t *ws;
	wchar_t *wpattern;
	ناپ_t len;
	صحيح ret;

	إذا ((len = mbstowcs(عدم, s, 0)) == (ناپ_t) -1)
		أرجع 0;
	ws = (wchar_t *) xcalloc(len + 1, حجم (wchar_t));
	mbstowcs(ws, s, len + 1);
	إذا ((len = mbstowcs(عدم, نمونہ, 0)) == (ناپ_t) -1) {
		حرر(ws);
		أرجع 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, حجم (wchar_t));
	mbstowcs(wpattern, نمونہ, len + 1);
	ret = __match_pattern (ws, wpattern);
	حرر(ws);
	حرر(wpattern);
	أرجع ret;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
صحيح
cygwin_ug_میل_نمونہ_list(ثابت حرف *string, ثابت حرف *نمونہ)
{
	حرف sub[1024];
	صحيح negated;
	صحيح got_مثبت;
	ناپ_t i, subi, len = لڑی_لمبائی(نمونہ);

	got_مثبت = 0;
	لكل (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		إذا (نمونہ[i] == '!') {
			negated = 1;
			i++;
		} وإلا
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		لكل (subi = 0;
		    i < len && subi < حجم(sub) - 1 && نمونہ[i] != ',';
		    subi++, i++)
			sub[subi] = نمونہ[i];
		/* If subpattern too long, return failure (no match). */
		إذا (subi >= حجم(sub) - 1)
			أرجع 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		إذا (i < len && نمونہ[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		إذا (میل_نمونہ_2(string, sub)) {
			إذا (negated)
				أرجع -1;		/* Negative */
			وإلا
				got_مثبت = 1;	/*مثبت*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	أرجع got_مثبت;
}

#جے_انت /* HAVE_CYGWIN */
