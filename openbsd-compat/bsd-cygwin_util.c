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

#وصف_ڪريو NO_ٻٽو_OPEN	/* Avoid redefining open to binary_open for this file */
#ضمن "includes.h"

#جيڪڏهن_وصف_ٿيل HAVE_CYGWIN

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
ٻٽو_open(ثابت حرف *filename, صحيح flags, ...)
{
	va_list ap;
	گهڻائي_t گهڻائي;

	va_start(ap, flags);
	گهڻائي = va_arg(ap, گهڻائي_t);
	va_end(ap);
	أرجع (open(filename, flags | O_ٻٽو, گهڻائي));
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
#جيڪڏهن_وصف_ٿيل CW_CYGNAME_FROM_WINNAME
      إذا (cygwin_اندروني (CW_CYGNAME_FROM_WINNAME, "sshd", cyg_privsep_user,
			   حجم cyg_privsep_user) != 0)
#جيڪڏهن_پورو
	strlcpy(cyg_privsep_user, "sshd", حجم(cyg_privsep_user));
    }
  أرجع cyg_privsep_user;
}

#وصف_ڪريو NL(x) x, (حجم (x) - 1)
#وصف_ڪريو WENV_SIZ (حجم (wenv_arr) / حجم (wenv_arr[0]))

ساكن بنية wenv {
	ثابت حرف *name;
	سائيز_t namelen;
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
	بنانشان صحيح i, idx = 0;

	p = xcalloc(WENV_SIZ + 1, حجم(حرف *));
	لكل (e = environ; *e != عدم; ++e) {
		لكل (i = 0; i < WENV_SIZ; ++i) {
			إذا (!لڙي_ڀيٽ(*e, wenv_arr[i].name, wenv_arr[i].namelen))
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
__match_pattern (ثابت wchar_t *s, ثابت wchar_t *نمونو)
{
	لكل (;;) {
		/* If at end of pattern, accept if also at end of string. */
		إذا (!*نمونو)
			أرجع !*s;

		إذا (*نمونو == '*') {
			/* Skip the asterisk. */
			نمونو++;

			/* If at end of pattern, accept immediately. */
			إذا (!*نمونو)
				أرجع 1;

			/* If next character in pattern is known, optimize. */
			إذا (*نمونو != '?' && *نمونو != '*') {
				/*
				 * Look instances of the next character in
				 * pattern, and try to match starting from
				 * those.
				 */
				لكل (; *s; s++)
					إذا (*s == *نمونو &&
					    __match_pattern(s + 1, نمونو + 1))
						أرجع 1;
				/* Failed. */
				أرجع 0;
			}
			/*
			 * Move ahead one character at a time and try to
			 * match at each position.
			 */
			لكل (; *s; s++)
				إذا (__match_pattern(s, نمونو))
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
		إذا (*نمونو != '?' && towlower(*نمونو) != towlower(*s))
			أرجع 0;

		/* Move to the next character, both in string and in pattern. */
		s++;
		نمونو++;
	}
	/* NOTREACHED */
}

ساكن صحيح
ميلاپ_نمونو_2(ثابت حرف *s, ثابت حرف *نمونو)
{
	wchar_t *ws;
	wchar_t *wpattern;
	سائيز_t len;
	صحيح ret;

	إذا ((len = mbstowcs(عدم, s, 0)) == (سائيز_t) -1)
		أرجع 0;
	ws = (wchar_t *) xcalloc(len + 1, حجم (wchar_t));
	mbstowcs(ws, s, len + 1);
	إذا ((len = mbstowcs(عدم, نمونو, 0)) == (سائيز_t) -1) {
		حرر(ws);
		أرجع 0;
	}
	wpattern = (wchar_t *) xcalloc(len + 1, حجم (wchar_t));
	mbstowcs(wpattern, نمونو, len + 1);
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
cygwin_ug_ميلاپ_نمونو_list(ثابت حرف *string, ثابت حرف *نمونو)
{
	حرف sub[1024];
	صحيح negated;
	صحيح got_مثبت;
	سائيز_t i, subi, len = لڙي_ڊيگهه(نمونو);

	got_مثبت = 0;
	لكل (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		إذا (نمونو[i] == '!') {
			negated = 1;
			i++;
		} وإلا
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		لكل (subi = 0;
		    i < len && subi < حجم(sub) - 1 && نمونو[i] != ',';
		    subi++, i++)
			sub[subi] = نمونو[i];
		/* If subpattern too long, return failure (no match). */
		إذا (subi >= حجم(sub) - 1)
			أرجع 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		إذا (i < len && نمونو[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		إذا (ميلاپ_نمونو_2(string, sub)) {
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

#جيڪڏهن_پورو /* HAVE_CYGWIN */
