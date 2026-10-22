/* $OpenBSD: utf8.c,v 1.11 2020/05/01 06:28:52 djm Exp $ */
/*
 * Copyright (c) 2016 Ingo Schwarze <schwarze@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Utility functions for multibyte-character handling,
 * in particular to sanitize untrusted strings for terminal output.
 */

#شامل "includes.h"

#شامل <sys/types.h>
#اگر_تعریف_شدہ HAVE_LANGINFO_H
# include <langinfo.h>
#اگر_ختم
#شامل <limits.h>
#شامل <locale.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#اگر defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_WCHAR_H
# include <wchar.h>
#اگر_ختم

#شامل "utf8.h"

ساکن صحیح	 dangerous_locale(خالی);
ساکن صحیح	 grow_dst(حرف **, سائز_t *, سائز_t, حرف **, سائز_t);


/*
 * For US-ASCII and UTF-8 encodings, we can safely recover from
 * encoding errors and from non-printable characters.  For any
 * other encodings, err to the side of caution and abort parsing:
 * For state-dependent encodings, recovery is impossible.
 * For arbitrary encodings, replacement of non-printable
 * characters would be non-trivial and too fragile.
 * The comments indicate what nl_langinfo(CODESET)
 * returns for US-ASCII on various operating systems.
 */

ساکن صحیح
dangerous_locale(خالی) {
	حرف	*loc;

	loc = nl_langinfo(CODESET);
	واپس strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

ساکن صحیح
grow_dst(حرف **dst, سائز_t *sz, سائز_t maxsz, حرف **dp, سائز_t need)
{
	حرف	*tp;
	سائز_t	 tsz;

	اگر (*dp + need < *dst + *sz)
		واپس 0;
	tsz = *sz + 128;
	اگر (tsz > maxsz)
		tsz = maxsz;
	اگر ((tp = recallocarray(*dst, *sz, tsz, 1)) == تہی)
		واپس -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	واپس 0;
}

/*
 * The following two functions limit the number of bytes written,
 * including the terminating '\0', to sz.  Unless wp is NULL,
 * they limit the number of display columns occupied to *wp.
 * Whichever is reached first terminates the output string.
 * To stay close to the standard interfaces, they return the number of
 * non-NUL bytes that would have been written if both were unlimited.
 * If wp is NULL, newline, carriage return, and tab are allowed;
 * otherwise, the actual number of columns occupied by what was
 * written is returned in *wp.
 */

صحیح
vasnmprintf(حرف **str, سائز_t maxsz, صحیح *wp, ثابت حرف *fmt, va_list ap)
{
	حرف	*src;	/* Source string returned from vasprintf. */
	حرف	*sp;	/* Pointer into src. */
	حرف	*dst;	/* Destination string to be returned. */
	حرف	*dp;	/* Pointer into dst. */
	حرف	*tp;	/* Temporary pointer for dst. */
	سائز_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	صحیح	 len;	/* Number of bytes in the character at sp. */
	صحیح	 ret;	/* Number of bytes needed to format src. */
	صحیح	 چوڑائی;	/* Display width of the character wc. */
	صحیح	 کل_چوڑائی, max_چوڑائی, print;

	src = تہی;
	اگر ((ret = vasprintf(&src, fmt, ap)) <= 0)
		جاؤ fail;

	sz = لڑی_لمبائی(src) + 1;
	اگر ((dst = حافظہ_دو(sz)) == تہی) {
		آزاد(src);
		ret = -1;
		جاؤ fail;
	}

	اگر (maxsz > زیادہ_سے_زیادہ_عدد)
		maxsz = زیادہ_سے_زیادہ_عدد;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	کل_چوڑائی = 0;
	max_چوڑائی = wp == تہی ? زیادہ_سے_زیادہ_عدد : *wp;
	جب (*sp != '\0') {
		اگر ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(خالی)mbtowc(تہی, تہی, MB_CUR_MAX);
			اگر (dangerous_locale()) {
				ret = -1;
				توڑو;
			}
			len = 1;
			چوڑائی = -1;
		} ورنہ اگر (wp == تہی &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			چوڑائی = 0;
		} ورنہ اگر ((چوڑائی = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			توڑو;
		}

		/* Valid, printable character. */

		اگر (چوڑائی >= 0) {
			اگر (print && (dp - dst >= (صحیح)maxsz - len ||
			    کل_چوڑائی > max_چوڑائی - چوڑائی))
				print = 0;
			اگر (print) {
				اگر (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					توڑو;
				}
				کل_چوڑائی += چوڑائی;
				حافظہ_نقل(dp, sp, len);
				dp += len;
			}
			sp += len;
			اگر (ret >= 0)
				ret += len;
			جاری;
		}

		/* Escaping required. */

		جب (len > 0) {
			اگر (print && (dp - dst >= (صحیح)maxsz - 4 ||
			    کل_چوڑائی > max_چوڑائی - 4))
				print = 0;
			اگر (print) {
				اگر (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					توڑو;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				چوڑائی = tp - dp;
				کل_چوڑائی += چوڑائی;
				dp = tp;
			} ورنہ
				چوڑائی = 4;
			len--;
			sp++;
			اگر (ret >= 0)
				ret += چوڑائی;
		}
		اگر (len > 0)
			توڑو;
	}
	آزاد(src);
	*dp = '\0';
	*str = dst;
	اگر (wp != تہی)
		*wp = کل_چوڑائی;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	اگر (ret < (صحیح)maxsz && !print)
		ret = -1;
	واپس ret;

fail:
	اگر (wp != تہی)
		*wp = 0;
	اگر (ret == 0) {
		*str = src;
		واپس 0;
	} ورنہ {
		*str = تہی;
		واپس -1;
	}
}

صحیح
snmprintf(حرف *str, سائز_t sz, صحیح *wp, ثابت حرف *fmt, ...)
{
	va_list	 ap;
	حرف	*cp = تہی;
	صحیح	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	اگر (cp != تہی) {
		(خالی)strlcpy(str, cp, sz);
		آزاد(cp);
	} ورنہ
		*str = '\0';
	واپس ret;
}

صحیح
asmprintf(حرف **outp, سائز_t sz, صحیح *wp, ثابت حرف *fmt, ...)
{
	va_list	 ap;
	صحیح	 ret;

	*outp = تہی;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	واپس ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

صحیح
vfmprintf(FILE *دھارا, ثابت حرف *fmt, va_list ap)
{
	حرف	*str = تہی;
	صحیح	 ret;

	اگر ((ret = vasnmprintf(&str, زیادہ_سے_زیادہ_عدد, تہی, fmt, ap)) < 0) {
		آزاد(str);
		واپس -1;
	}
	اگر (fputs(str, دھارا) == EOF)
		ret = -1;
	آزاد(str);
	واپس ret;
}

صحیح
fmprintf(FILE *دھارا, ثابت حرف *fmt, ...)
{
	va_list	 ap;
	صحیح	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(دھارا, fmt, ap);
	va_end(ap);
	واپس ret;
}

صحیح
mprintf(ثابت حرف *fmt, ...)
{
	va_list	 ap;
	صحیح	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	واپس ret;
}

/*
 * Set up libc for multibyte output in the user's chosen locale.
 *
 * XXX: we are known to have problems with Turkic languages (i/I confusion) so
 *      we deliberately fall back to the C locale for now. Longer term we
 *      should always prefer to select C.[encoding] if possible, but there's
 *      no standardisation in locales between systems, so we'll need to survey
 *      what's out there first.
 * XXX: alternately runtime probe that toupper('i') != 'I' and vice-versa?
 */
خالی
msetlocale(خالی)
{
	ثابت حرف *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", تہی };
	حرف *cp;
	صحیح i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	برائے (i = 0; vars[i] != تہی; i++) {
		اگر ((cp = getenv(vars[i])) == تہی)
			جاری;
		اگر (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			توڑو;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		اگر ((strcasestr(cp, "UTF-8") != تہی ||
		    strcasestr(cp, "UTF8") != تہی) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != تہی ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != تہی))
			واپس;
		setlocale(LC_CTYPE, "C");
		واپس;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
