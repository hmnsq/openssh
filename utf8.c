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

#include "includes.h"

#include <sys/types.h>
#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif
#include <limits.h>
#include <locale.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#如果 defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#include "utf8.h"

static 整数	 dangerous_locale(void);
static 整数	 grow_dst(char **, size_t *, size_t, char **, size_t);


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

static 整数
dangerous_locale(void) {
	char	*loc;

	loc = nl_langinfo(CODESET);
	返回 strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

static 整数
grow_dst(char **dst, size_t *sz, size_t maxsz, char **dp, size_t need)
{
	char	*tp;
	size_t	 tsz;

	如果 (*dp + need < *dst + *sz)
		返回 0;
	tsz = *sz + 128;
	如果 (tsz > maxsz)
		tsz = maxsz;
	如果 ((tp = recallocarray(*dst, *sz, tsz, 1)) == NULL)
		返回 -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	返回 0;
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

整数
vasnmprintf(char **str, size_t maxsz, 整数 *wp, const char *fmt, va_list ap)
{
	char	*src;	/* Source string returned from vasprintf. */
	char	*sp;	/* Pointer into src. */
	char	*dst;	/* Destination string to be returned. */
	char	*dp;	/* Pointer into dst. */
	char	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	整数	 len;	/* Number of bytes in the character at sp. */
	整数	 ret;	/* Number of bytes needed to format src. */
	整数	 width;	/* Display width of the character wc. */
	整数	 total_width, max_width, print;

	src = NULL;
	如果 ((ret = vasprintf(&src, fmt, ap)) <= 0)
		goto fail;

	sz = strlen(src) + 1;
	如果 ((dst = malloc(sz)) == NULL) {
		free(src);
		ret = -1;
		goto fail;
	}

	如果 (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == NULL ? INT_MAX : *wp;
	当 (*sp != '\0') {
		如果 ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(void)mbtowc(NULL, NULL, MB_CUR_MAX);
			如果 (dangerous_locale()) {
				ret = -1;
				break;
			}
			len = 1;
			width = -1;
		} 否则 如果 (wp == NULL &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} 否则 如果 ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			break;
		}

		/* Valid, printable character. */

		如果 (width >= 0) {
			如果 (print && (dp - dst >= (整数)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			如果 (print) {
				如果 (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					break;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			如果 (ret >= 0)
				ret += len;
			continue;
		}

		/* Escaping required. */

		当 (len > 0) {
			如果 (print && (dp - dst >= (整数)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			如果 (print) {
				如果 (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					break;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} 否则
				width = 4;
			len--;
			sp++;
			如果 (ret >= 0)
				ret += width;
		}
		如果 (len > 0)
			break;
	}
	free(src);
	*dp = '\0';
	*str = dst;
	如果 (wp != NULL)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	如果 (ret < (整数)maxsz && !print)
		ret = -1;
	返回 ret;

fail:
	如果 (wp != NULL)
		*wp = 0;
	如果 (ret == 0) {
		*str = src;
		返回 0;
	} 否则 {
		*str = NULL;
		返回 -1;
	}
}

整数
snmprintf(char *str, size_t sz, 整数 *wp, const char *fmt, ...)
{
	va_list	 ap;
	char	*cp = NULL;
	整数	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	如果 (cp != NULL) {
		(void)strlcpy(str, cp, sz);
		free(cp);
	} 否则
		*str = '\0';
	返回 ret;
}

整数
asmprintf(char **outp, size_t sz, 整数 *wp, const char *fmt, ...)
{
	va_list	 ap;
	整数	 ret;

	*outp = NULL;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	返回 ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

整数
vfmprintf(FILE *stream, const char *fmt, va_list ap)
{
	char	*str = NULL;
	整数	 ret;

	如果 ((ret = vasnmprintf(&str, INT_MAX, NULL, fmt, ap)) < 0) {
		free(str);
		返回 -1;
	}
	如果 (fputs(str, stream) == EOF)
		ret = -1;
	free(str);
	返回 ret;
}

整数
fmprintf(FILE *stream, const char *fmt, ...)
{
	va_list	 ap;
	整数	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	返回 ret;
}

整数
mprintf(const char *fmt, ...)
{
	va_list	 ap;
	整数	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	返回 ret;
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
void
msetlocale(void)
{
	const char *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", NULL };
	char *cp;
	整数 i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	为 (i = 0; vars[i] != NULL; i++) {
		如果 ((cp = getenv(vars[i])) == NULL)
			continue;
		如果 (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			break;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		如果 ((strcasestr(cp, "UTF-8") != NULL ||
		    strcasestr(cp, "UTF8") != NULL) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != NULL ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != NULL))
			返回;
		setlocale(LC_CTYPE, "C");
		返回;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
