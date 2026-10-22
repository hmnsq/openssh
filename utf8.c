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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <locale.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಯದಿ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#ಅನ್ತರ್ಭಾವ "utf8.h"

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 dangerous_locale(ಶೂನ್ಯ);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ	 grow_dst(ವರ್ಣ **, size_t *, size_t, ವರ್ಣ **, size_t);


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

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
dangerous_locale(ಶೂನ್ಯ) {
	ವರ್ಣ	*loc;

	loc = nl_langinfo(CODESET);
	ಪ್ರತ್ಯಾಗಮ strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
grow_dst(ವರ್ಣ **dst, size_t *sz, size_t maxsz, ವರ್ಣ **dp, size_t need)
{
	ವರ್ಣ	*tp;
	size_t	 tsz;

	ಯದಿ (*dp + need < *dst + *sz)
		ಪ್ರತ್ಯಾಗಮ 0;
	tsz = *sz + 128;
	ಯದಿ (tsz > maxsz)
		tsz = maxsz;
	ಯದಿ ((tp = recallocarray(*dst, *sz, tsz, 1)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	ಪ್ರತ್ಯಾಗಮ 0;
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

ಪೂರ್ಣಾಙ್ಕ
vasnmprintf(ವರ್ಣ **str, size_t maxsz, ಪೂರ್ಣಾಙ್ಕ *wp, ಧ್ರುವ ವರ್ಣ *fmt, va_list ap)
{
	ವರ್ಣ	*src;	/* Source string returned from vasprintf. */
	ವರ್ಣ	*sp;	/* Pointer into src. */
	ವರ್ಣ	*dst;	/* Destination string to be returned. */
	ವರ್ಣ	*dp;	/* Pointer into dst. */
	ವರ್ಣ	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	ಪೂರ್ಣಾಙ್ಕ	 len;	/* Number of bytes in the character at sp. */
	ಪೂರ್ಣಾಙ್ಕ	 ret;	/* Number of bytes needed to format src. */
	ಪೂರ್ಣಾಙ್ಕ	 width;	/* Display width of the character wc. */
	ಪೂರ್ಣಾಙ್ಕ	 total_width, max_width, print;

	src = ರಿಕ್ತ;
	ಯದಿ ((ret = vasprintf(&src, fmt, ap)) <= 0)
		ಗಚ್ಛ fail;

	sz = strlen(src) + 1;
	ಯದಿ ((dst = malloc(sz)) == ರಿಕ್ತ) {
		ಮುಕ್ತ(src);
		ret = -1;
		ಗಚ್ಛ fail;
	}

	ಯದಿ (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == ರಿಕ್ತ ? INT_MAX : *wp;
	ಯಾವತ್ (*sp != '\0') {
		ಯದಿ ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(ಶೂನ್ಯ)mbtowc(ರಿಕ್ತ, ರಿಕ್ತ, MB_CUR_MAX);
			ಯದಿ (dangerous_locale()) {
				ret = -1;
				ಭಙ್ಗ;
			}
			len = 1;
			width = -1;
		} ಅನ್ಯಥಾ ಯದಿ (wp == ರಿಕ್ತ &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} ಅನ್ಯಥಾ ಯದಿ ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			ಭಙ್ಗ;
		}

		/* Valid, printable character. */

		ಯದಿ (width >= 0) {
			ಯದಿ (print && (dp - dst >= (ಪೂರ್ಣಾಙ್ಕ)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			ಯದಿ (print) {
				ಯದಿ (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					ಭಙ್ಗ;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			ಯದಿ (ret >= 0)
				ret += len;
			ಅನುವರ್ತ;
		}

		/* Escaping required. */

		ಯಾವತ್ (len > 0) {
			ಯದಿ (print && (dp - dst >= (ಪೂರ್ಣಾಙ್ಕ)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			ಯದಿ (print) {
				ಯದಿ (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					ಭಙ್ಗ;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} ಅನ್ಯಥಾ
				width = 4;
			len--;
			sp++;
			ಯದಿ (ret >= 0)
				ret += width;
		}
		ಯದಿ (len > 0)
			ಭಙ್ಗ;
	}
	ಮುಕ್ತ(src);
	*dp = '\0';
	*str = dst;
	ಯದಿ (wp != ರಿಕ್ತ)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	ಯದಿ (ret < (ಪೂರ್ಣಾಙ್ಕ)maxsz && !print)
		ret = -1;
	ಪ್ರತ್ಯಾಗಮ ret;

fail:
	ಯದಿ (wp != ರಿಕ್ತ)
		*wp = 0;
	ಯದಿ (ret == 0) {
		*str = src;
		ಪ್ರತ್ಯಾಗಮ 0;
	} ಅನ್ಯಥಾ {
		*str = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಪೂರ್ಣಾಙ್ಕ
snmprintf(ವರ್ಣ *str, size_t sz, ಪೂರ್ಣಾಙ್ಕ *wp, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list	 ap;
	ವರ್ಣ	*cp = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	ಯದಿ (cp != ರಿಕ್ತ) {
		(ಶೂನ್ಯ)strlcpy(str, cp, sz);
		ಮುಕ್ತ(cp);
	} ಅನ್ಯಥಾ
		*str = '\0';
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
asmprintf(ವರ್ಣ **outp, size_t sz, ಪೂರ್ಣಾಙ್ಕ *wp, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list	 ap;
	ಪೂರ್ಣಾಙ್ಕ	 ret;

	*outp = ರಿಕ್ತ;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

ಪೂರ್ಣಾಙ್ಕ
vfmprintf(FILE *stream, ಧ್ರುವ ವರ್ಣ *fmt, va_list ap)
{
	ವರ್ಣ	*str = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ	 ret;

	ಯದಿ ((ret = vasnmprintf(&str, INT_MAX, ರಿಕ್ತ, fmt, ap)) < 0) {
		ಮುಕ್ತ(str);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (fputs(str, stream) == EOF)
		ret = -1;
	ಮುಕ್ತ(str);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
fmprintf(FILE *stream, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list	 ap;
	ಪೂರ್ಣಾಙ್ಕ	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
mprintf(ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list	 ap;
	ಪೂರ್ಣಾಙ್ಕ	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	ಪ್ರತ್ಯಾಗಮ ret;
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
ಶೂನ್ಯ
msetlocale(ಶೂನ್ಯ)
{
	ಧ್ರುವ ವರ್ಣ *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", ರಿಕ್ತ };
	ವರ್ಣ *cp;
	ಪೂರ್ಣಾಙ್ಕ i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	ಪ್ರತಿ (i = 0; vars[i] != ರಿಕ್ತ; i++) {
		ಯದಿ ((cp = getenv(vars[i])) == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			ಭಙ್ಗ;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		ಯದಿ ((strcasestr(cp, "UTF-8") != ರಿಕ್ತ ||
		    strcasestr(cp, "UTF8") != ರಿಕ್ತ) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != ರಿಕ್ತ ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != ರಿಕ್ತ))
			ಪ್ರತ್ಯಾಗಮ;
		setlocale(LC_CTYPE, "C");
		ಪ್ರತ್ಯಾಗಮ;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
