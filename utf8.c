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
#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif
#شامل <limits.h>
#شامل <locale.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#اگر defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#شامل "utf8.h"

ایستا صحیح	 dangerous_locale(تهی);
ایستا صحیح	 grow_dst(نویسه **, size_t *, size_t, نویسه **, size_t);


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

ایستا صحیح
dangerous_locale(تهی) {
	نویسه	*loc;

	loc = nl_langinfo(CODESET);
	بازگشت strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

ایستا صحیح
grow_dst(نویسه **dst, size_t *sz, size_t maxsz, نویسه **dp, size_t need)
{
	نویسه	*tp;
	size_t	 tsz;

	اگر (*dp + need < *dst + *sz)
		بازگشت 0;
	tsz = *sz + 128;
	اگر (tsz > maxsz)
		tsz = maxsz;
	اگر ((tp = recallocarray(*dst, *sz, tsz, 1)) == پوچ)
		بازگشت -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	بازگشت 0;
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
vasnmprintf(نویسه **str, size_t maxsz, صحیح *wp, ثابت نویسه *fmt, va_list ap)
{
	نویسه	*src;	/* Source string returned from vasprintf. */
	نویسه	*sp;	/* Pointer into src. */
	نویسه	*dst;	/* Destination string to be returned. */
	نویسه	*dp;	/* Pointer into dst. */
	نویسه	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	صحیح	 len;	/* Number of bytes in the character at sp. */
	صحیح	 ret;	/* Number of bytes needed to format src. */
	صحیح	 width;	/* Display width of the character wc. */
	صحیح	 total_width, max_width, print;

	src = پوچ;
	اگر ((ret = vasprintf(&src, fmt, ap)) <= 0)
		برو fail;

	sz = strlen(src) + 1;
	اگر ((dst = malloc(sz)) == پوچ) {
		آزاد(src);
		ret = -1;
		برو fail;
	}

	اگر (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == پوچ ? INT_MAX : *wp;
	وقتی (*sp != '\0') {
		اگر ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(تهی)mbtowc(پوچ, پوچ, MB_CUR_MAX);
			اگر (dangerous_locale()) {
				ret = -1;
				بشکن;
			}
			len = 1;
			width = -1;
		} وگرنه اگر (wp == پوچ &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} وگرنه اگر ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			بشکن;
		}

		/* Valid, printable character. */

		اگر (width >= 0) {
			اگر (print && (dp - dst >= (صحیح)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			اگر (print) {
				اگر (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					بشکن;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			اگر (ret >= 0)
				ret += len;
			ادامه;
		}

		/* Escaping required. */

		وقتی (len > 0) {
			اگر (print && (dp - dst >= (صحیح)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			اگر (print) {
				اگر (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					بشکن;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} وگرنه
				width = 4;
			len--;
			sp++;
			اگر (ret >= 0)
				ret += width;
		}
		اگر (len > 0)
			بشکن;
	}
	آزاد(src);
	*dp = '\0';
	*str = dst;
	اگر (wp != پوچ)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	اگر (ret < (صحیح)maxsz && !print)
		ret = -1;
	بازگشت ret;

fail:
	اگر (wp != پوچ)
		*wp = 0;
	اگر (ret == 0) {
		*str = src;
		بازگشت 0;
	} وگرنه {
		*str = پوچ;
		بازگشت -1;
	}
}

صحیح
snmprintf(نویسه *str, size_t sz, صحیح *wp, ثابت نویسه *fmt, ...)
{
	va_list	 ap;
	نویسه	*cp = پوچ;
	صحیح	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	اگر (cp != پوچ) {
		(تهی)strlcpy(str, cp, sz);
		آزاد(cp);
	} وگرنه
		*str = '\0';
	بازگشت ret;
}

صحیح
asmprintf(نویسه **outp, size_t sz, صحیح *wp, ثابت نویسه *fmt, ...)
{
	va_list	 ap;
	صحیح	 ret;

	*outp = پوچ;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	بازگشت ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

صحیح
vfmprintf(FILE *stream, ثابت نویسه *fmt, va_list ap)
{
	نویسه	*str = پوچ;
	صحیح	 ret;

	اگر ((ret = vasnmprintf(&str, INT_MAX, پوچ, fmt, ap)) < 0) {
		آزاد(str);
		بازگشت -1;
	}
	اگر (fputs(str, stream) == EOF)
		ret = -1;
	آزاد(str);
	بازگشت ret;
}

صحیح
fmprintf(FILE *stream, ثابت نویسه *fmt, ...)
{
	va_list	 ap;
	صحیح	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	بازگشت ret;
}

صحیح
mprintf(ثابت نویسه *fmt, ...)
{
	va_list	 ap;
	صحیح	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	بازگشت ret;
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
تهی
msetlocale(تهی)
{
	ثابت نویسه *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", پوچ };
	نویسه *cp;
	صحیح i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	برای (i = 0; vars[i] != پوچ; i++) {
		اگر ((cp = getenv(vars[i])) == پوچ)
			ادامه;
		اگر (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			بشکن;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		اگر ((strcasestr(cp, "UTF-8") != پوچ ||
		    strcasestr(cp, "UTF8") != پوچ) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != پوچ ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != پوچ))
			بازگشت;
		setlocale(LC_CTYPE, "C");
		بازگشت;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
