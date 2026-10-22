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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif
#अन्तर्भाव <limits.h>
#अन्तर्भाव <locale.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#यदि defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#अन्तर्भाव "utf8.h"

स्थिर पूर्णाङ्क	 dangerous_locale(शून्य);
स्थिर पूर्णाङ्क	 grow_dst(वर्ण **, size_t *, size_t, वर्ण **, size_t);


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

स्थिर पूर्णाङ्क
dangerous_locale(शून्य) {
	वर्ण	*loc;

	loc = nl_langinfo(CODESET);
	प्रत्यागम strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

स्थिर पूर्णाङ्क
grow_dst(वर्ण **dst, size_t *sz, size_t maxsz, वर्ण **dp, size_t need)
{
	वर्ण	*tp;
	size_t	 tsz;

	यदि (*dp + need < *dst + *sz)
		प्रत्यागम 0;
	tsz = *sz + 128;
	यदि (tsz > maxsz)
		tsz = maxsz;
	यदि ((tp = recallocarray(*dst, *sz, tsz, 1)) == रिक्त)
		प्रत्यागम -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	प्रत्यागम 0;
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

पूर्णाङ्क
vasnmprintf(वर्ण **str, size_t maxsz, पूर्णाङ्क *wp, ध्रुव वर्ण *fmt, va_list ap)
{
	वर्ण	*src;	/* Source string returned from vasprintf. */
	वर्ण	*sp;	/* Pointer into src. */
	वर्ण	*dst;	/* Destination string to be returned. */
	वर्ण	*dp;	/* Pointer into dst. */
	वर्ण	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	पूर्णाङ्क	 len;	/* Number of bytes in the character at sp. */
	पूर्णाङ्क	 ret;	/* Number of bytes needed to format src. */
	पूर्णाङ्क	 width;	/* Display width of the character wc. */
	पूर्णाङ्क	 total_width, max_width, print;

	src = रिक्त;
	यदि ((ret = vasprintf(&src, fmt, ap)) <= 0)
		गच्छ fail;

	sz = strlen(src) + 1;
	यदि ((dst = malloc(sz)) == रिक्त) {
		मुक्त(src);
		ret = -1;
		गच्छ fail;
	}

	यदि (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == रिक्त ? INT_MAX : *wp;
	यावत् (*sp != '\0') {
		यदि ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(शून्य)mbtowc(रिक्त, रिक्त, MB_CUR_MAX);
			यदि (dangerous_locale()) {
				ret = -1;
				भङ्ग;
			}
			len = 1;
			width = -1;
		} अन्यथा यदि (wp == रिक्त &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} अन्यथा यदि ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			भङ्ग;
		}

		/* Valid, printable character. */

		यदि (width >= 0) {
			यदि (print && (dp - dst >= (पूर्णाङ्क)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			यदि (print) {
				यदि (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					भङ्ग;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			यदि (ret >= 0)
				ret += len;
			अनुवर्त;
		}

		/* Escaping required. */

		यावत् (len > 0) {
			यदि (print && (dp - dst >= (पूर्णाङ्क)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			यदि (print) {
				यदि (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					भङ्ग;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} अन्यथा
				width = 4;
			len--;
			sp++;
			यदि (ret >= 0)
				ret += width;
		}
		यदि (len > 0)
			भङ्ग;
	}
	मुक्त(src);
	*dp = '\0';
	*str = dst;
	यदि (wp != रिक्त)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	यदि (ret < (पूर्णाङ्क)maxsz && !print)
		ret = -1;
	प्रत्यागम ret;

fail:
	यदि (wp != रिक्त)
		*wp = 0;
	यदि (ret == 0) {
		*str = src;
		प्रत्यागम 0;
	} अन्यथा {
		*str = रिक्त;
		प्रत्यागम -1;
	}
}

पूर्णाङ्क
snmprintf(वर्ण *str, size_t sz, पूर्णाङ्क *wp, ध्रुव वर्ण *fmt, ...)
{
	va_list	 ap;
	वर्ण	*cp = रिक्त;
	पूर्णाङ्क	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	यदि (cp != रिक्त) {
		(शून्य)strlcpy(str, cp, sz);
		मुक्त(cp);
	} अन्यथा
		*str = '\0';
	प्रत्यागम ret;
}

पूर्णाङ्क
asmprintf(वर्ण **outp, size_t sz, पूर्णाङ्क *wp, ध्रुव वर्ण *fmt, ...)
{
	va_list	 ap;
	पूर्णाङ्क	 ret;

	*outp = रिक्त;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	प्रत्यागम ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

पूर्णाङ्क
vfmprintf(FILE *stream, ध्रुव वर्ण *fmt, va_list ap)
{
	वर्ण	*str = रिक्त;
	पूर्णाङ्क	 ret;

	यदि ((ret = vasnmprintf(&str, INT_MAX, रिक्त, fmt, ap)) < 0) {
		मुक्त(str);
		प्रत्यागम -1;
	}
	यदि (fputs(str, stream) == EOF)
		ret = -1;
	मुक्त(str);
	प्रत्यागम ret;
}

पूर्णाङ्क
fmprintf(FILE *stream, ध्रुव वर्ण *fmt, ...)
{
	va_list	 ap;
	पूर्णाङ्क	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	प्रत्यागम ret;
}

पूर्णाङ्क
mprintf(ध्रुव वर्ण *fmt, ...)
{
	va_list	 ap;
	पूर्णाङ्क	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	प्रत्यागम ret;
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
शून्य
msetlocale(शून्य)
{
	ध्रुव वर्ण *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", रिक्त };
	वर्ण *cp;
	पूर्णाङ्क i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	प्रति (i = 0; vars[i] != रिक्त; i++) {
		यदि ((cp = getenv(vars[i])) == रिक्त)
			अनुवर्त;
		यदि (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			भङ्ग;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		यदि ((strcasestr(cp, "UTF-8") != रिक्त ||
		    strcasestr(cp, "UTF8") != रिक्त) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != रिक्त ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != रिक्त))
			प्रत्यागम;
		setlocale(LC_CTYPE, "C");
		प्रत्यागम;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
