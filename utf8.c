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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif
#ضمن <limits.h>
#ضمن <locale.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#إذا defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#ضمن "utf8.h"

ساكن صحيح	 dangerous_locale(فراغ);
ساكن صحيح	 grow_dst(حرف **, size_t *, size_t, حرف **, size_t);


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

ساكن صحيح
dangerous_locale(فراغ) {
	حرف	*loc;

	loc = nl_langinfo(CODESET);
	أرجع strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

ساكن صحيح
grow_dst(حرف **dst, size_t *sz, size_t maxsz, حرف **dp, size_t need)
{
	حرف	*tp;
	size_t	 tsz;

	إذا (*dp + need < *dst + *sz)
		أرجع 0;
	tsz = *sz + 128;
	إذا (tsz > maxsz)
		tsz = maxsz;
	إذا ((tp = recallocarray(*dst, *sz, tsz, 1)) == عدم)
		أرجع -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	أرجع 0;
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

صحيح
vasnmprintf(حرف **str, size_t maxsz, صحيح *wp, ثابت حرف *fmt, va_list ap)
{
	حرف	*src;	/* Source string returned from vasprintf. */
	حرف	*sp;	/* Pointer into src. */
	حرف	*dst;	/* Destination string to be returned. */
	حرف	*dp;	/* Pointer into dst. */
	حرف	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	صحيح	 len;	/* Number of bytes in the character at sp. */
	صحيح	 ret;	/* Number of bytes needed to format src. */
	صحيح	 width;	/* Display width of the character wc. */
	صحيح	 total_width, max_width, اطبع;

	src = عدم;
	إذا ((ret = vasprintf(&src, fmt, ap)) <= 0)
		اذهب fail;

	sz = strlen(src) + 1;
	إذا ((dst = malloc(sz)) == عدم) {
		حرر(src);
		ret = -1;
		اذهب fail;
	}

	إذا (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	اطبع = 1;
	total_width = 0;
	max_width = wp == عدم ? INT_MAX : *wp;
	طالما (*sp != '\0') {
		إذا ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(فراغ)mbtowc(عدم, عدم, MB_CUR_MAX);
			إذا (dangerous_locale()) {
				ret = -1;
				اكسر;
			}
			len = 1;
			width = -1;
		} وإلا إذا (wp == عدم &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} وإلا إذا ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			اكسر;
		}

		/* Valid, printable character. */

		إذا (width >= 0) {
			إذا (اطبع && (dp - dst >= (صحيح)maxsz - len ||
			    total_width > max_width - width))
				اطبع = 0;
			إذا (اطبع) {
				إذا (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					اكسر;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			إذا (ret >= 0)
				ret += len;
			استمر;
		}

		/* Escaping required. */

		طالما (len > 0) {
			إذا (اطبع && (dp - dst >= (صحيح)maxsz - 4 ||
			    total_width > max_width - 4))
				اطبع = 0;
			إذا (اطبع) {
				إذا (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					اكسر;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} وإلا
				width = 4;
			len--;
			sp++;
			إذا (ret >= 0)
				ret += width;
		}
		إذا (len > 0)
			اكسر;
	}
	حرر(src);
	*dp = '\0';
	*str = dst;
	إذا (wp != عدم)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	إذا (ret < (صحيح)maxsz && !اطبع)
		ret = -1;
	أرجع ret;

fail:
	إذا (wp != عدم)
		*wp = 0;
	إذا (ret == 0) {
		*str = src;
		أرجع 0;
	} وإلا {
		*str = عدم;
		أرجع -1;
	}
}

صحيح
snmprintf(حرف *str, size_t sz, صحيح *wp, ثابت حرف *fmt, ...)
{
	va_list	 ap;
	حرف	*cp = عدم;
	صحيح	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	إذا (cp != عدم) {
		(فراغ)strlcpy(str, cp, sz);
		حرر(cp);
	} وإلا
		*str = '\0';
	أرجع ret;
}

صحيح
asmprintf(حرف **outp, size_t sz, صحيح *wp, ثابت حرف *fmt, ...)
{
	va_list	 ap;
	صحيح	 ret;

	*outp = عدم;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	أرجع ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

صحيح
vfmprintf(FILE *stream, ثابت حرف *fmt, va_list ap)
{
	حرف	*str = عدم;
	صحيح	 ret;

	إذا ((ret = vasnmprintf(&str, INT_MAX, عدم, fmt, ap)) < 0) {
		حرر(str);
		أرجع -1;
	}
	إذا (fputs(str, stream) == EOF)
		ret = -1;
	حرر(str);
	أرجع ret;
}

صحيح
fmprintf(FILE *stream, ثابت حرف *fmt, ...)
{
	va_list	 ap;
	صحيح	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	أرجع ret;
}

صحيح
mprintf(ثابت حرف *fmt, ...)
{
	va_list	 ap;
	صحيح	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	أرجع ret;
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
فراغ
msetlocale(فراغ)
{
	ثابت حرف *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", عدم };
	حرف *cp;
	صحيح i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	لكل (i = 0; vars[i] != عدم; i++) {
		إذا ((cp = getenv(vars[i])) == عدم)
			استمر;
		إذا (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			اكسر;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		إذا ((strcasestr(cp, "UTF-8") != عدم ||
		    strcasestr(cp, "UTF8") != عدم) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != عدم ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != عدم))
			أرجع;
		setlocale(LC_CTYPE, "C");
		أرجع;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
