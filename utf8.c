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

স্থির পূর্ণাঙ্ক	 dangerous_locale(শূন্য);
স্থির পূর্ণাঙ্ক	 grow_dst(বর্ণ **, size_t *, size_t, বর্ণ **, size_t);


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

স্থির পূর্ণাঙ্ক
dangerous_locale(শূন্য) {
	বর্ণ	*loc;

	loc = nl_langinfo(CODESET);
	প্রত্যাগম strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

স্থির পূর্ণাঙ্ক
grow_dst(বর্ণ **dst, size_t *sz, size_t maxsz, বর্ণ **dp, size_t need)
{
	বর্ণ	*tp;
	size_t	 tsz;

	যদি (*dp + need < *dst + *sz)
		প্রত্যাগম 0;
	tsz = *sz + 128;
	যদি (tsz > maxsz)
		tsz = maxsz;
	যদি ((tp = recallocarray(*dst, *sz, tsz, 1)) == রিক্ত)
		প্রত্যাগম -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	প্রত্যাগম 0;
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

পূর্ণাঙ্ক
vasnmprintf(বর্ণ **str, size_t maxsz, পূর্ণাঙ্ক *wp, ধ্রুব বর্ণ *fmt, va_list ap)
{
	বর্ণ	*src;	/* Source string returned from vasprintf. */
	বর্ণ	*sp;	/* Pointer into src. */
	বর্ণ	*dst;	/* Destination string to be returned. */
	বর্ণ	*dp;	/* Pointer into dst. */
	বর্ণ	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	পূর্ণাঙ্ক	 len;	/* Number of bytes in the character at sp. */
	পূর্ণাঙ্ক	 ret;	/* Number of bytes needed to format src. */
	পূর্ণাঙ্ক	 width;	/* Display width of the character wc. */
	পূর্ণাঙ্ক	 total_width, max_width, print;

	src = রিক্ত;
	যদি ((ret = vasprintf(&src, fmt, ap)) <= 0)
		গচ্ছ fail;

	sz = strlen(src) + 1;
	যদি ((dst = malloc(sz)) == রিক্ত) {
		মুক্ত(src);
		ret = -1;
		গচ্ছ fail;
	}

	যদি (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == রিক্ত ? INT_MAX : *wp;
	যাবত্ (*sp != '\0') {
		যদি ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(শূন্য)mbtowc(রিক্ত, রিক্ত, MB_CUR_MAX);
			যদি (dangerous_locale()) {
				ret = -1;
				ভঙ্গ;
			}
			len = 1;
			width = -1;
		} অন্যথা যদি (wp == রিক্ত &&
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
			ভঙ্গ;
		}

		/* Valid, printable character. */

		যদি (width >= 0) {
			যদি (print && (dp - dst >= (পূর্ণাঙ্ক)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			যদি (print) {
				যদি (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					ভঙ্গ;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			যদি (ret >= 0)
				ret += len;
			অনুবর্ত;
		}

		/* Escaping required. */

		যাবত্ (len > 0) {
			যদি (print && (dp - dst >= (পূর্ণাঙ্ক)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			যদি (print) {
				যদি (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					ভঙ্গ;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} অন্যথা
				width = 4;
			len--;
			sp++;
			যদি (ret >= 0)
				ret += width;
		}
		যদি (len > 0)
			ভঙ্গ;
	}
	মুক্ত(src);
	*dp = '\0';
	*str = dst;
	যদি (wp != রিক্ত)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	যদি (ret < (পূর্ণাঙ্ক)maxsz && !print)
		ret = -1;
	প্রত্যাগম ret;

fail:
	যদি (wp != রিক্ত)
		*wp = 0;
	যদি (ret == 0) {
		*str = src;
		প্রত্যাগম 0;
	} অন্যথা {
		*str = রিক্ত;
		প্রত্যাগম -1;
	}
}

পূর্ণাঙ্ক
snmprintf(বর্ণ *str, size_t sz, পূর্ণাঙ্ক *wp, ধ্রুব বর্ণ *fmt, ...)
{
	va_list	 ap;
	বর্ণ	*cp = রিক্ত;
	পূর্ণাঙ্ক	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	যদি (cp != রিক্ত) {
		(শূন্য)strlcpy(str, cp, sz);
		মুক্ত(cp);
	} অন্যথা
		*str = '\0';
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
asmprintf(বর্ণ **outp, size_t sz, পূর্ণাঙ্ক *wp, ধ্রুব বর্ণ *fmt, ...)
{
	va_list	 ap;
	পূর্ণাঙ্ক	 ret;

	*outp = রিক্ত;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	প্রত্যাগম ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

পূর্ণাঙ্ক
vfmprintf(FILE *stream, ধ্রুব বর্ণ *fmt, va_list ap)
{
	বর্ণ	*str = রিক্ত;
	পূর্ণাঙ্ক	 ret;

	যদি ((ret = vasnmprintf(&str, INT_MAX, রিক্ত, fmt, ap)) < 0) {
		মুক্ত(str);
		প্রত্যাগম -1;
	}
	যদি (fputs(str, stream) == EOF)
		ret = -1;
	মুক্ত(str);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
fmprintf(FILE *stream, ধ্রুব বর্ণ *fmt, ...)
{
	va_list	 ap;
	পূর্ণাঙ্ক	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
mprintf(ধ্রুব বর্ণ *fmt, ...)
{
	va_list	 ap;
	পূর্ণাঙ্ক	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	প্রত্যাগম ret;
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
	ধ্রুব বর্ণ *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", রিক্ত };
	বর্ণ *cp;
	পূর্ণাঙ্ক i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	প্রতি (i = 0; vars[i] != রিক্ত; i++) {
		যদি ((cp = getenv(vars[i])) == রিক্ত)
			অনুবর্ত;
		যদি (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			ভঙ্গ;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		যদি ((strcasestr(cp, "UTF-8") != রিক্ত ||
		    strcasestr(cp, "UTF8") != রিক্ত) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != রিক্ত ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != রিক্ত))
			প্রত্যাগম;
		setlocale(LC_CTYPE, "C");
		প্রত্যাগম;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
