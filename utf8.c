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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <locale.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#જો defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#અન્તર્ભાવ "utf8.h"

સ્થિર પૂર્ણાંક	 dangerous_locale(શૂન્ય);
સ્થિર પૂર્ણાંક	 grow_dst(અક્ષર **, size_t *, size_t, અક્ષર **, size_t);


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

સ્થિર પૂર્ણાંક
dangerous_locale(શૂન્ય) {
	અક્ષર	*loc;

	loc = nl_langinfo(CODESET);
	પાછા strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

સ્થિર પૂર્ણાંક
grow_dst(અક્ષર **dst, size_t *sz, size_t maxsz, અક્ષર **dp, size_t need)
{
	અક્ષર	*tp;
	size_t	 tsz;

	જો (*dp + need < *dst + *sz)
		પાછા 0;
	tsz = *sz + 128;
	જો (tsz > maxsz)
		tsz = maxsz;
	જો ((tp = recallocarray(*dst, *sz, tsz, 1)) == ખાલી)
		પાછા -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	પાછા 0;
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

પૂર્ણાંક
vasnmprintf(અક્ષર **str, size_t maxsz, પૂર્ણાંક *wp, અચલ અક્ષર *fmt, va_list ap)
{
	અક્ષર	*src;	/* Source string returned from vasprintf. */
	અક્ષર	*sp;	/* Pointer into src. */
	અક્ષર	*dst;	/* Destination string to be returned. */
	અક્ષર	*dp;	/* Pointer into dst. */
	અક્ષર	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	પૂર્ણાંક	 len;	/* Number of bytes in the character at sp. */
	પૂર્ણાંક	 ret;	/* Number of bytes needed to format src. */
	પૂર્ણાંક	 width;	/* Display width of the character wc. */
	પૂર્ણાંક	 total_width, max_width, print;

	src = ખાલી;
	જો ((ret = vasprintf(&src, fmt, ap)) <= 0)
		જાઓ fail;

	sz = strlen(src) + 1;
	જો ((dst = malloc(sz)) == ખાલી) {
		મુક્ત(src);
		ret = -1;
		જાઓ fail;
	}

	જો (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == ખાલી ? INT_MAX : *wp;
	જ્યારે (*sp != '\0') {
		જો ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(શૂન્ય)mbtowc(ખાલી, ખાલી, MB_CUR_MAX);
			જો (dangerous_locale()) {
				ret = -1;
				તોડો;
			}
			len = 1;
			width = -1;
		} નહીંતર જો (wp == ખાલી &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} નહીંતર જો ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			તોડો;
		}

		/* Valid, printable character. */

		જો (width >= 0) {
			જો (print && (dp - dst >= (પૂર્ણાંક)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			જો (print) {
				જો (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					તોડો;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			જો (ret >= 0)
				ret += len;
			ચાલુ;
		}

		/* Escaping required. */

		જ્યારે (len > 0) {
			જો (print && (dp - dst >= (પૂર્ણાંક)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			જો (print) {
				જો (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					તોડો;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} નહીંતર
				width = 4;
			len--;
			sp++;
			જો (ret >= 0)
				ret += width;
		}
		જો (len > 0)
			તોડો;
	}
	મુક્ત(src);
	*dp = '\0';
	*str = dst;
	જો (wp != ખાલી)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	જો (ret < (પૂર્ણાંક)maxsz && !print)
		ret = -1;
	પાછા ret;

fail:
	જો (wp != ખાલી)
		*wp = 0;
	જો (ret == 0) {
		*str = src;
		પાછા 0;
	} નહીંતર {
		*str = ખાલી;
		પાછા -1;
	}
}

પૂર્ણાંક
snmprintf(અક્ષર *str, size_t sz, પૂર્ણાંક *wp, અચલ અક્ષર *fmt, ...)
{
	va_list	 ap;
	અક્ષર	*cp = ખાલી;
	પૂર્ણાંક	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	જો (cp != ખાલી) {
		(શૂન્ય)strlcpy(str, cp, sz);
		મુક્ત(cp);
	} નહીંતર
		*str = '\0';
	પાછા ret;
}

પૂર્ણાંક
asmprintf(અક્ષર **outp, size_t sz, પૂર્ણાંક *wp, અચલ અક્ષર *fmt, ...)
{
	va_list	 ap;
	પૂર્ણાંક	 ret;

	*outp = ખાલી;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	પાછા ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

પૂર્ણાંક
vfmprintf(FILE *stream, અચલ અક્ષર *fmt, va_list ap)
{
	અક્ષર	*str = ખાલી;
	પૂર્ણાંક	 ret;

	જો ((ret = vasnmprintf(&str, INT_MAX, ખાલી, fmt, ap)) < 0) {
		મુક્ત(str);
		પાછા -1;
	}
	જો (fputs(str, stream) == EOF)
		ret = -1;
	મુક્ત(str);
	પાછા ret;
}

પૂર્ણાંક
fmprintf(FILE *stream, અચલ અક્ષર *fmt, ...)
{
	va_list	 ap;
	પૂર્ણાંક	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	પાછા ret;
}

પૂર્ણાંક
mprintf(અચલ અક્ષર *fmt, ...)
{
	va_list	 ap;
	પૂર્ણાંક	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	પાછા ret;
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
શૂન્ય
msetlocale(શૂન્ય)
{
	અચલ અક્ષર *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", ખાલી };
	અક્ષર *cp;
	પૂર્ણાંક i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	માટે (i = 0; vars[i] != ખાલી; i++) {
		જો ((cp = getenv(vars[i])) == ખાલી)
			ચાલુ;
		જો (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			તોડો;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		જો ((strcasestr(cp, "UTF-8") != ખાલી ||
		    strcasestr(cp, "UTF8") != ખાલી) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != ખાલી ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != ખાલી))
			પાછા;
		setlocale(LC_CTYPE, "C");
		પાછા;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
