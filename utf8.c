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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <locale.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#যদি defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#অন্তর্ভাব "utf8.h"

স্থির পূর্ণসংখ্যা	 dangerous_locale(শূন্য);
স্থির পূর্ণসংখ্যা	 grow_dst(অক্ষর **, আকার_t *, আকার_t, অক্ষর **, আকার_t);


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

স্থির পূর্ণসংখ্যা
dangerous_locale(শূন্য) {
	অক্ষর	*loc;

	loc = nl_langinfo(CODESET);
	ফেরত strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

স্থির পূর্ণসংখ্যা
grow_dst(অক্ষর **dst, আকার_t *sz, আকার_t maxsz, অক্ষর **dp, আকার_t need)
{
	অক্ষর	*tp;
	আকার_t	 tsz;

	যদি (*dp + need < *dst + *sz)
		ফেরত 0;
	tsz = *sz + 128;
	যদি (tsz > maxsz)
		tsz = maxsz;
	যদি ((tp = recallocarray(*dst, *sz, tsz, 1)) == ফাঁকা)
		ফেরত -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	ফেরত 0;
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

পূর্ণসংখ্যা
vasnmprintf(অক্ষর **str, আকার_t maxsz, পূর্ণসংখ্যা *wp, ধ্রুবক অক্ষর *fmt, va_list ap)
{
	অক্ষর	*src;	/* Source string returned from vasprintf. */
	অক্ষর	*sp;	/* Pointer into src. */
	অক্ষর	*dst;	/* Destination string to be returned. */
	অক্ষর	*dp;	/* Pointer into dst. */
	অক্ষর	*tp;	/* Temporary pointer for dst. */
	আকার_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	পূর্ণসংখ্যা	 len;	/* Number of bytes in the character at sp. */
	পূর্ণসংখ্যা	 ret;	/* Number of bytes needed to format src. */
	পূর্ণসংখ্যা	 width;	/* Display width of the character wc. */
	পূর্ণসংখ্যা	 যোগ_width, max_width, print;

	src = ফাঁকা;
	যদি ((ret = vasprintf(&src, fmt, ap)) <= 0)
		যাও fail;

	sz = strlen(src) + 1;
	যদি ((dst = malloc(sz)) == ফাঁকা) {
		মুক্ত(src);
		ret = -1;
		যাও fail;
	}

	যদি (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	যোগ_width = 0;
	max_width = wp == ফাঁকা ? INT_MAX : *wp;
	যখন (*sp != '\0') {
		যদি ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(শূন্য)mbtowc(ফাঁকা, ফাঁকা, MB_CUR_MAX);
			যদি (dangerous_locale()) {
				ret = -1;
				বিরতি;
			}
			len = 1;
			width = -1;
		} অন্যথা যদি (wp == ফাঁকা &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} অন্যথা যদি ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			বিরতি;
		}

		/* Valid, printable character. */

		যদি (width >= 0) {
			যদি (print && (dp - dst >= (পূর্ণসংখ্যা)maxsz - len ||
			    যোগ_width > max_width - width))
				print = 0;
			যদি (print) {
				যদি (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					বিরতি;
				}
				যোগ_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			যদি (ret >= 0)
				ret += len;
			চালু;
		}

		/* Escaping required. */

		যখন (len > 0) {
			যদি (print && (dp - dst >= (পূর্ণসংখ্যা)maxsz - 4 ||
			    যোগ_width > max_width - 4))
				print = 0;
			যদি (print) {
				যদি (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					বিরতি;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				যোগ_width += width;
				dp = tp;
			} অন্যথা
				width = 4;
			len--;
			sp++;
			যদি (ret >= 0)
				ret += width;
		}
		যদি (len > 0)
			বিরতি;
	}
	মুক্ত(src);
	*dp = '\0';
	*str = dst;
	যদি (wp != ফাঁকা)
		*wp = যোগ_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	যদি (ret < (পূর্ণসংখ্যা)maxsz && !print)
		ret = -1;
	ফেরত ret;

fail:
	যদি (wp != ফাঁকা)
		*wp = 0;
	যদি (ret == 0) {
		*str = src;
		ফেরত 0;
	} অন্যথা {
		*str = ফাঁকা;
		ফেরত -1;
	}
}

পূর্ণসংখ্যা
snmprintf(অক্ষর *str, আকার_t sz, পূর্ণসংখ্যা *wp, ধ্রুবক অক্ষর *fmt, ...)
{
	va_list	 ap;
	অক্ষর	*cp = ফাঁকা;
	পূর্ণসংখ্যা	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	যদি (cp != ফাঁকা) {
		(শূন্য)strlcpy(str, cp, sz);
		মুক্ত(cp);
	} অন্যথা
		*str = '\0';
	ফেরত ret;
}

পূর্ণসংখ্যা
asmprintf(অক্ষর **outp, আকার_t sz, পূর্ণসংখ্যা *wp, ধ্রুবক অক্ষর *fmt, ...)
{
	va_list	 ap;
	পূর্ণসংখ্যা	 ret;

	*outp = ফাঁকা;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	ফেরত ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

পূর্ণসংখ্যা
vfmprintf(FILE *stream, ধ্রুবক অক্ষর *fmt, va_list ap)
{
	অক্ষর	*str = ফাঁকা;
	পূর্ণসংখ্যা	 ret;

	যদি ((ret = vasnmprintf(&str, INT_MAX, ফাঁকা, fmt, ap)) < 0) {
		মুক্ত(str);
		ফেরত -1;
	}
	যদি (fputs(str, stream) == EOF)
		ret = -1;
	মুক্ত(str);
	ফেরত ret;
}

পূর্ণসংখ্যা
fmprintf(FILE *stream, ধ্রুবক অক্ষর *fmt, ...)
{
	va_list	 ap;
	পূর্ণসংখ্যা	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	ফেরত ret;
}

পূর্ণসংখ্যা
mprintf(ধ্রুবক অক্ষর *fmt, ...)
{
	va_list	 ap;
	পূর্ণসংখ্যা	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	ফেরত ret;
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
শূন্য
msetlocale(শূন্য)
{
	ধ্রুবক অক্ষর *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", ফাঁকা };
	অক্ষর *cp;
	পূর্ণসংখ্যা i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	জন্য (i = 0; vars[i] != ফাঁকা; i++) {
		যদি ((cp = getenv(vars[i])) == ফাঁকা)
			চালু;
		যদি (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			বিরতি;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		যদি ((strcasestr(cp, "UTF-8") != ফাঁকা ||
		    strcasestr(cp, "UTF8") != ফাঁকা) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != ফাঁকা ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != ফাঁকা))
			ফেরত;
		setlocale(LC_CTYPE, "C");
		ফেরত;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
