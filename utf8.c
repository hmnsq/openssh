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
#නම් defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#include "utf8.h"

static පූර්ණ_සංඛ්‍යා	 dangerous_locale(void);
static පූර්ණ_සංඛ්‍යා	 grow_dst(var_na **, size_t *, size_t, var_na **, size_t);


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

static පූර්ණ_සංඛ්‍යා
dangerous_locale(void) {
	var_na	*loc;

	loc = nl_langinfo(CODESET);
	ආපසු strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

static පූර්ණ_සංඛ්‍යා
grow_dst(var_na **dst, size_t *sz, size_t maxsz, var_na **dp, size_t need)
{
	var_na	*tp;
	size_t	 tsz;

	නම් (*dp + need < *dst + *sz)
		ආපසු 0;
	tsz = *sz + 128;
	නම් (tsz > maxsz)
		tsz = maxsz;
	නම් ((tp = recallocarray(*dst, *sz, tsz, 1)) == NULL)
		ආපසු -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	ආපසු 0;
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

පූර්ණ_සංඛ්‍යා
vasnmprintf(var_na **str, size_t maxsz, පූර්ණ_සංඛ්‍යා *wp, const var_na *fmt, va_list ap)
{
	var_na	*src;	/* Source string returned from vasprintf. */
	var_na	*sp;	/* Pointer into src. */
	var_na	*dst;	/* Destination string to be returned. */
	var_na	*dp;	/* Pointer into dst. */
	var_na	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	පූර්ණ_සංඛ්‍යා	 len;	/* Number of bytes in the character at sp. */
	පූර්ණ_සංඛ්‍යා	 ret;	/* Number of bytes needed to format src. */
	පූර්ණ_සංඛ්‍යා	 width;	/* Display width of the character wc. */
	පූර්ණ_සංඛ්‍යා	 total_width, max_width, print;

	src = NULL;
	නම් ((ret = vasprintf(&src, fmt, ap)) <= 0)
		goto fail;

	sz = strlen(src) + 1;
	නම් ((dst = malloc(sz)) == NULL) {
		free(src);
		ret = -1;
		goto fail;
	}

	නම් (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == NULL ? INT_MAX : *wp;
	අතරතුර (*sp != '\0') {
		නම් ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(void)mbtowc(NULL, NULL, MB_CUR_MAX);
			නම් (dangerous_locale()) {
				ret = -1;
				bha_nga;
			}
			len = 1;
			width = -1;
		} නැතහොත් නම් (wp == NULL &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} නැතහොත් නම් ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			bha_nga;
		}

		/* Valid, printable character. */

		නම් (width >= 0) {
			නම් (print && (dp - dst >= (පූර්ණ_සංඛ්‍යා)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			නම් (print) {
				නම් (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					bha_nga;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			නම් (ret >= 0)
				ret += len;
			continue;
		}

		/* Escaping required. */

		අතරතුර (len > 0) {
			නම් (print && (dp - dst >= (පූර්ණ_සංඛ්‍යා)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			නම් (print) {
				නම් (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					bha_nga;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} නැතහොත්
				width = 4;
			len--;
			sp++;
			නම් (ret >= 0)
				ret += width;
		}
		නම් (len > 0)
			bha_nga;
	}
	free(src);
	*dp = '\0';
	*str = dst;
	නම් (wp != NULL)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	නම් (ret < (පූර්ණ_සංඛ්‍යා)maxsz && !print)
		ret = -1;
	ආපසු ret;

fail:
	නම් (wp != NULL)
		*wp = 0;
	නම් (ret == 0) {
		*str = src;
		ආපසු 0;
	} නැතහොත් {
		*str = NULL;
		ආපසු -1;
	}
}

පූර්ණ_සංඛ්‍යා
snmprintf(var_na *str, size_t sz, පූර්ණ_සංඛ්‍යා *wp, const var_na *fmt, ...)
{
	va_list	 ap;
	var_na	*cp = NULL;
	පූර්ණ_සංඛ්‍යා	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	නම් (cp != NULL) {
		(void)strlcpy(str, cp, sz);
		free(cp);
	} නැතහොත්
		*str = '\0';
	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
asmprintf(var_na **outp, size_t sz, පූර්ණ_සංඛ්‍යා *wp, const var_na *fmt, ...)
{
	va_list	 ap;
	පූර්ණ_සංඛ්‍යා	 ret;

	*outp = NULL;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	ආපසු ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

පූර්ණ_සංඛ්‍යා
vfmprintf(FILE *stream, const var_na *fmt, va_list ap)
{
	var_na	*str = NULL;
	පූර්ණ_සංඛ්‍යා	 ret;

	නම් ((ret = vasnmprintf(&str, INT_MAX, NULL, fmt, ap)) < 0) {
		free(str);
		ආපසු -1;
	}
	නම් (fputs(str, stream) == EOF)
		ret = -1;
	free(str);
	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
fmprintf(FILE *stream, const var_na *fmt, ...)
{
	va_list	 ap;
	පූර්ණ_සංඛ්‍යා	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
mprintf(const var_na *fmt, ...)
{
	va_list	 ap;
	පූර්ණ_සංඛ්‍යා	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	ආපසු ret;
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
	const var_na *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", NULL };
	var_na *cp;
	පූර්ණ_සංඛ්‍යා i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	සඳහා (i = 0; vars[i] != NULL; i++) {
		නම් ((cp = getenv(vars[i])) == NULL)
			continue;
		නම් (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			bha_nga;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		නම් ((strcasestr(cp, "UTF-8") != NULL ||
		    strcasestr(cp, "UTF8") != NULL) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != NULL ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != NULL))
			ආපසු;
		setlocale(LC_CTYPE, "C");
		ආපසු;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
