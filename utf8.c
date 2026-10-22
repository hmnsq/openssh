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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <locale.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଯଦି defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#ଅନ୍ତର୍ଭାଵ "utf8.h"

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 dangerous_locale(ଶୂନ୍ୟ);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 grow_dst(ଅକ୍ଷର **, size_t *, size_t, ଅକ୍ଷର **, size_t);


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

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
dangerous_locale(ଶୂନ୍ୟ) {
	ଅକ୍ଷର	*loc;

	loc = nl_langinfo(CODESET);
	ଫେରନ୍ତୁ strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
grow_dst(ଅକ୍ଷର **dst, size_t *sz, size_t maxsz, ଅକ୍ଷର **dp, size_t need)
{
	ଅକ୍ଷର	*tp;
	size_t	 tsz;

	ଯଦି (*dp + need < *dst + *sz)
		ଫେରନ୍ତୁ 0;
	tsz = *sz + 128;
	ଯଦି (tsz > maxsz)
		tsz = maxsz;
	ଯଦି ((tp = recallocarray(*dst, *sz, tsz, 1)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	ଫେରନ୍ତୁ 0;
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

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
vasnmprintf(ଅକ୍ଷର **str, size_t maxsz, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *wp, ଅଚଳ ଅକ୍ଷର *fmt, va_list ap)
{
	ଅକ୍ଷର	*src;	/* Source string returned from vasprintf. */
	ଅକ୍ଷର	*sp;	/* Pointer into src. */
	ଅକ୍ଷର	*dst;	/* Destination string to be returned. */
	ଅକ୍ଷର	*dp;	/* Pointer into dst. */
	ଅକ୍ଷର	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 len;	/* Number of bytes in the character at sp. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ret;	/* Number of bytes needed to format src. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 width;	/* Display width of the character wc. */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 total_width, max_width, print;

	src = ଖାଲି;
	ଯଦି ((ret = vasprintf(&src, fmt, ap)) <= 0)
		ଯାଅ fail;

	sz = strlen(src) + 1;
	ଯଦି ((dst = malloc(sz)) == ଖାଲି) {
		ମୁକ୍ତ(src);
		ret = -1;
		ଯାଅ fail;
	}

	ଯଦି (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == ଖାଲି ? INT_MAX : *wp;
	ଯେତେବେଳେ (*sp != '\0') {
		ଯଦି ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(ଶୂନ୍ୟ)mbtowc(ଖାଲି, ଖାଲି, MB_CUR_MAX);
			ଯଦି (dangerous_locale()) {
				ret = -1;
				ଭାଙ୍ଗ;
			}
			len = 1;
			width = -1;
		} ଅନ୍ୟଥା ଯଦି (wp == ଖାଲି &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} ଅନ୍ୟଥା ଯଦି ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			ଭାଙ୍ଗ;
		}

		/* Valid, printable character. */

		ଯଦି (width >= 0) {
			ଯଦି (print && (dp - dst >= (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			ଯଦି (print) {
				ଯଦି (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					ଭାଙ୍ଗ;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			ଯଦି (ret >= 0)
				ret += len;
			ଜାରି;
		}

		/* Escaping required. */

		ଯେତେବେଳେ (len > 0) {
			ଯଦି (print && (dp - dst >= (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			ଯଦି (print) {
				ଯଦି (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					ଭାଙ୍ଗ;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} ଅନ୍ୟଥା
				width = 4;
			len--;
			sp++;
			ଯଦି (ret >= 0)
				ret += width;
		}
		ଯଦି (len > 0)
			ଭାଙ୍ଗ;
	}
	ମୁକ୍ତ(src);
	*dp = '\0';
	*str = dst;
	ଯଦି (wp != ଖାଲି)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	ଯଦି (ret < (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)maxsz && !print)
		ret = -1;
	ଫେରନ୍ତୁ ret;

fail:
	ଯଦି (wp != ଖାଲି)
		*wp = 0;
	ଯଦି (ret == 0) {
		*str = src;
		ଫେରନ୍ତୁ 0;
	} ଅନ୍ୟଥା {
		*str = ଖାଲି;
		ଫେରନ୍ତୁ -1;
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
snmprintf(ଅକ୍ଷର *str, size_t sz, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *wp, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list	 ap;
	ଅକ୍ଷର	*cp = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	ଯଦି (cp != ଖାଲି) {
		(ଶୂନ୍ୟ)strlcpy(str, cp, sz);
		ମୁକ୍ତ(cp);
	} ଅନ୍ୟଥା
		*str = '\0';
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
asmprintf(ଅକ୍ଷର **outp, size_t sz, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *wp, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list	 ap;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ret;

	*outp = ଖାଲି;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	ଫେରନ୍ତୁ ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
vfmprintf(FILE *stream, ଅଚଳ ଅକ୍ଷର *fmt, va_list ap)
{
	ଅକ୍ଷର	*str = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ret;

	ଯଦି ((ret = vasnmprintf(&str, INT_MAX, ଖାଲି, fmt, ap)) < 0) {
		ମୁକ୍ତ(str);
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (fputs(str, stream) == EOF)
		ret = -1;
	ମୁକ୍ତ(str);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fmprintf(FILE *stream, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list	 ap;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mprintf(ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list	 ap;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	ଫେରନ୍ତୁ ret;
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
ଶୂନ୍ୟ
msetlocale(ଶୂନ୍ୟ)
{
	ଅଚଳ ଅକ୍ଷର *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", ଖାଲି };
	ଅକ୍ଷର *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	ପାଇଁ (i = 0; vars[i] != ଖାଲି; i++) {
		ଯଦି ((cp = getenv(vars[i])) == ଖାଲି)
			ଜାରି;
		ଯଦି (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			ଭାଙ୍ଗ;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		ଯଦି ((strcasestr(cp, "UTF-8") != ଖାଲି ||
		    strcasestr(cp, "UTF8") != ଖାଲି) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != ଖାଲି ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != ଖାଲି))
			ଫେରନ୍ତୁ;
		setlocale(LC_CTYPE, "C");
		ଫେରନ୍ତୁ;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
