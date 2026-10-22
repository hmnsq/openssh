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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LANGINFO_H
# include <langinfo.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <locale.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਜੇ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_WCHAR_H
# include <wchar.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "utf8.h"

ਸਥਿਰ ਪੂਰਨ	 dangerous_locale(ਖਾਲੀ);
ਸਥਿਰ ਪੂਰਨ	 grow_dst(ਅੱਖਰ **, ਮਾਪ_t *, ਮਾਪ_t, ਅੱਖਰ **, ਮਾਪ_t);


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

ਸਥਿਰ ਪੂਰਨ
dangerous_locale(ਖਾਲੀ) {
	ਅੱਖਰ	*loc;

	loc = nl_langinfo(CODESET);
	ਵਾਪਸ strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

ਸਥਿਰ ਪੂਰਨ
grow_dst(ਅੱਖਰ **dst, ਮਾਪ_t *sz, ਮਾਪ_t maxsz, ਅੱਖਰ **dp, ਮਾਪ_t need)
{
	ਅੱਖਰ	*tp;
	ਮਾਪ_t	 tsz;

	ਜੇ (*dp + need < *dst + *sz)
		ਵਾਪਸ 0;
	tsz = *sz + 128;
	ਜੇ (tsz > maxsz)
		tsz = maxsz;
	ਜੇ ((tp = recallocarray(*dst, *sz, tsz, 1)) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	ਵਾਪਸ 0;
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

ਪੂਰਨ
vasnmprintf(ਅੱਖਰ **str, ਮਾਪ_t maxsz, ਪੂਰਨ *wp, ਅਚਲ ਅੱਖਰ *fmt, va_list ap)
{
	ਅੱਖਰ	*src;	/* Source string returned from vasprintf. */
	ਅੱਖਰ	*sp;	/* Pointer into src. */
	ਅੱਖਰ	*dst;	/* Destination string to be returned. */
	ਅੱਖਰ	*dp;	/* Pointer into dst. */
	ਅੱਖਰ	*tp;	/* Temporary pointer for dst. */
	ਮਾਪ_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	ਪੂਰਨ	 len;	/* Number of bytes in the character at sp. */
	ਪੂਰਨ	 ret;	/* Number of bytes needed to format src. */
	ਪੂਰਨ	 ਚੌੜਾਈ;	/* Display width of the character wc. */
	ਪੂਰਨ	 ਕੁੱਲ_ਚੌੜਾਈ, max_ਚੌੜਾਈ, print;

	src = ਨਿਰਾ;
	ਜੇ ((ret = vasprintf(&src, fmt, ap)) <= 0)
		ਜਾਓ fail;

	sz = ਲੜੀ_ਲੰਬਾਈ(src) + 1;
	ਜੇ ((dst = ਸਮ੍ਰਿਤੀ_ਦਿਓ(sz)) == ਨਿਰਾ) {
		ਮੁਕਤ(src);
		ret = -1;
		ਜਾਓ fail;
	}

	ਜੇ (maxsz > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		maxsz = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	ਕੁੱਲ_ਚੌੜਾਈ = 0;
	max_ਚੌੜਾਈ = wp == ਨਿਰਾ ? ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ : *wp;
	ਜਦੋਂ (*sp != '\0') {
		ਜੇ ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(ਖਾਲੀ)mbtowc(ਨਿਰਾ, ਨਿਰਾ, MB_CUR_MAX);
			ਜੇ (dangerous_locale()) {
				ret = -1;
				ਰੋਕੋ;
			}
			len = 1;
			ਚੌੜਾਈ = -1;
		} ਨਹੀਂਤਾਂ ਜੇ (wp == ਨਿਰਾ &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			ਚੌੜਾਈ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ ((ਚੌੜਾਈ = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			ਰੋਕੋ;
		}

		/* Valid, printable character. */

		ਜੇ (ਚੌੜਾਈ >= 0) {
			ਜੇ (print && (dp - dst >= (ਪੂਰਨ)maxsz - len ||
			    ਕੁੱਲ_ਚੌੜਾਈ > max_ਚੌੜਾਈ - ਚੌੜਾਈ))
				print = 0;
			ਜੇ (print) {
				ਜੇ (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					ਰੋਕੋ;
				}
				ਕੁੱਲ_ਚੌੜਾਈ += ਚੌੜਾਈ;
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(dp, sp, len);
				dp += len;
			}
			sp += len;
			ਜੇ (ret >= 0)
				ret += len;
			ਜਾਰੀ;
		}

		/* Escaping required. */

		ਜਦੋਂ (len > 0) {
			ਜੇ (print && (dp - dst >= (ਪੂਰਨ)maxsz - 4 ||
			    ਕੁੱਲ_ਚੌੜਾਈ > max_ਚੌੜਾਈ - 4))
				print = 0;
			ਜੇ (print) {
				ਜੇ (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					ਰੋਕੋ;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				ਚੌੜਾਈ = tp - dp;
				ਕੁੱਲ_ਚੌੜਾਈ += ਚੌੜਾਈ;
				dp = tp;
			} ਨਹੀਂਤਾਂ
				ਚੌੜਾਈ = 4;
			len--;
			sp++;
			ਜੇ (ret >= 0)
				ret += ਚੌੜਾਈ;
		}
		ਜੇ (len > 0)
			ਰੋਕੋ;
	}
	ਮੁਕਤ(src);
	*dp = '\0';
	*str = dst;
	ਜੇ (wp != ਨਿਰਾ)
		*wp = ਕੁੱਲ_ਚੌੜਾਈ;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	ਜੇ (ret < (ਪੂਰਨ)maxsz && !print)
		ret = -1;
	ਵਾਪਸ ret;

fail:
	ਜੇ (wp != ਨਿਰਾ)
		*wp = 0;
	ਜੇ (ret == 0) {
		*str = src;
		ਵਾਪਸ 0;
	} ਨਹੀਂਤਾਂ {
		*str = ਨਿਰਾ;
		ਵਾਪਸ -1;
	}
}

ਪੂਰਨ
snmprintf(ਅੱਖਰ *str, ਮਾਪ_t sz, ਪੂਰਨ *wp, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list	 ap;
	ਅੱਖਰ	*cp = ਨਿਰਾ;
	ਪੂਰਨ	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	ਜੇ (cp != ਨਿਰਾ) {
		(ਖਾਲੀ)strlcpy(str, cp, sz);
		ਮੁਕਤ(cp);
	} ਨਹੀਂਤਾਂ
		*str = '\0';
	ਵਾਪਸ ret;
}

ਪੂਰਨ
asmprintf(ਅੱਖਰ **outp, ਮਾਪ_t sz, ਪੂਰਨ *wp, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list	 ap;
	ਪੂਰਨ	 ret;

	*outp = ਨਿਰਾ;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	ਵਾਪਸ ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

ਪੂਰਨ
vfmprintf(FILE *ਧਾਰਾ, ਅਚਲ ਅੱਖਰ *fmt, va_list ap)
{
	ਅੱਖਰ	*str = ਨਿਰਾ;
	ਪੂਰਨ	 ret;

	ਜੇ ((ret = vasnmprintf(&str, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, ਨਿਰਾ, fmt, ap)) < 0) {
		ਮੁਕਤ(str);
		ਵਾਪਸ -1;
	}
	ਜੇ (fputs(str, ਧਾਰਾ) == EOF)
		ret = -1;
	ਮੁਕਤ(str);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
fmprintf(FILE *ਧਾਰਾ, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list	 ap;
	ਪੂਰਨ	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(ਧਾਰਾ, fmt, ap);
	va_end(ap);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
mprintf(ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list	 ap;
	ਪੂਰਨ	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	ਵਾਪਸ ret;
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
ਖਾਲੀ
msetlocale(ਖਾਲੀ)
{
	ਅਚਲ ਅੱਖਰ *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", ਨਿਰਾ };
	ਅੱਖਰ *cp;
	ਪੂਰਨ i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	ਲਈ (i = 0; vars[i] != ਨਿਰਾ; i++) {
		ਜੇ ((cp = getenv(vars[i])) == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			ਰੋਕੋ;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		ਜੇ ((strcasestr(cp, "UTF-8") != ਨਿਰਾ ||
		    strcasestr(cp, "UTF8") != ਨਿਰਾ) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != ਨਿਰਾ ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != ਨਿਰਾ))
			ਵਾਪਸ;
		setlocale(LC_CTYPE, "C");
		ਵਾਪਸ;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
