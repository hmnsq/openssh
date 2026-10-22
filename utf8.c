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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <locale.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#எனில் defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#அந்தர்பாவ "utf8.h"

நிலையான முழு	 dangerous_locale(வெறுமை);
நிலையான முழு	 grow_dst(எழுத்து **, size_t *, size_t, எழுத்து **, size_t);


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

நிலையான முழு
dangerous_locale(வெறுமை) {
	எழுத்து	*loc;

	loc = nl_langinfo(CODESET);
	திரும்பு strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

நிலையான முழு
grow_dst(எழுத்து **dst, size_t *sz, size_t maxsz, எழுத்து **dp, size_t need)
{
	எழுத்து	*tp;
	size_t	 tsz;

	எனில் (*dp + need < *dst + *sz)
		திரும்பு 0;
	tsz = *sz + 128;
	எனில் (tsz > maxsz)
		tsz = maxsz;
	எனில் ((tp = recallocarray(*dst, *sz, tsz, 1)) == வெற்று)
		திரும்பு -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	திரும்பு 0;
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

முழு
vasnmprintf(எழுத்து **str, size_t maxsz, முழு *wp, மாறிலி எழுத்து *fmt, va_list ap)
{
	எழுத்து	*src;	/* Source string returned from vasprintf. */
	எழுத்து	*sp;	/* Pointer into src. */
	எழுத்து	*dst;	/* Destination string to be returned. */
	எழுத்து	*dp;	/* Pointer into dst. */
	எழுத்து	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	முழு	 len;	/* Number of bytes in the character at sp. */
	முழு	 ret;	/* Number of bytes needed to format src. */
	முழு	 width;	/* Display width of the character wc. */
	முழு	 total_width, max_width, print;

	src = வெற்று;
	எனில் ((ret = vasprintf(&src, fmt, ap)) <= 0)
		செல் fail;

	sz = strlen(src) + 1;
	எனில் ((dst = malloc(sz)) == வெற்று) {
		விடுவி(src);
		ret = -1;
		செல் fail;
	}

	எனில் (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == வெற்று ? INT_MAX : *wp;
	போது (*sp != '\0') {
		எனில் ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(வெறுமை)mbtowc(வெற்று, வெற்று, MB_CUR_MAX);
			எனில் (dangerous_locale()) {
				ret = -1;
				நிறுத்து;
			}
			len = 1;
			width = -1;
		} இல்லையெனில் எனில் (wp == வெற்று &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} இல்லையெனில் எனில் ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			நிறுத்து;
		}

		/* Valid, printable character. */

		எனில் (width >= 0) {
			எனில் (print && (dp - dst >= (முழு)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			எனில் (print) {
				எனில் (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					நிறுத்து;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			எனில் (ret >= 0)
				ret += len;
			தொடர்;
		}

		/* Escaping required. */

		போது (len > 0) {
			எனில் (print && (dp - dst >= (முழு)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			எனில் (print) {
				எனில் (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					நிறுத்து;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} இல்லையெனில்
				width = 4;
			len--;
			sp++;
			எனில் (ret >= 0)
				ret += width;
		}
		எனில் (len > 0)
			நிறுத்து;
	}
	விடுவி(src);
	*dp = '\0';
	*str = dst;
	எனில் (wp != வெற்று)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	எனில் (ret < (முழு)maxsz && !print)
		ret = -1;
	திரும்பு ret;

fail:
	எனில் (wp != வெற்று)
		*wp = 0;
	எனில் (ret == 0) {
		*str = src;
		திரும்பு 0;
	} இல்லையெனில் {
		*str = வெற்று;
		திரும்பு -1;
	}
}

முழு
snmprintf(எழுத்து *str, size_t sz, முழு *wp, மாறிலி எழுத்து *fmt, ...)
{
	va_list	 ap;
	எழுத்து	*cp = வெற்று;
	முழு	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	எனில் (cp != வெற்று) {
		(வெறுமை)strlcpy(str, cp, sz);
		விடுவி(cp);
	} இல்லையெனில்
		*str = '\0';
	திரும்பு ret;
}

முழு
asmprintf(எழுத்து **outp, size_t sz, முழு *wp, மாறிலி எழுத்து *fmt, ...)
{
	va_list	 ap;
	முழு	 ret;

	*outp = வெற்று;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	திரும்பு ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

முழு
vfmprintf(FILE *stream, மாறிலி எழுத்து *fmt, va_list ap)
{
	எழுத்து	*str = வெற்று;
	முழு	 ret;

	எனில் ((ret = vasnmprintf(&str, INT_MAX, வெற்று, fmt, ap)) < 0) {
		விடுவி(str);
		திரும்பு -1;
	}
	எனில் (fputs(str, stream) == EOF)
		ret = -1;
	விடுவி(str);
	திரும்பு ret;
}

முழு
fmprintf(FILE *stream, மாறிலி எழுத்து *fmt, ...)
{
	va_list	 ap;
	முழு	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	திரும்பு ret;
}

முழு
mprintf(மாறிலி எழுத்து *fmt, ...)
{
	va_list	 ap;
	முழு	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	திரும்பு ret;
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
வெறுமை
msetlocale(வெறுமை)
{
	மாறிலி எழுத்து *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", வெற்று };
	எழுத்து *cp;
	முழு i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	க்கு (i = 0; vars[i] != வெற்று; i++) {
		எனில் ((cp = getenv(vars[i])) == வெற்று)
			தொடர்;
		எனில் (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			நிறுத்து;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		எனில் ((strcasestr(cp, "UTF-8") != வெற்று ||
		    strcasestr(cp, "UTF8") != வெற்று) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != வெற்று ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != வெற்று))
			திரும்பு;
		setlocale(LC_CTYPE, "C");
		திரும்பு;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
