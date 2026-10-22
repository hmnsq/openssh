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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <locale.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#എങ്കിൽ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#അന്തര്ഭാവ "utf8.h"

സ്ഥിതം പൂർണ്ണസംഖ്യ	 dangerous_locale(ശൂന്യം);
സ്ഥിതം പൂർണ്ണസംഖ്യ	 grow_dst(അക്ഷരം **, size_t *, size_t, അക്ഷരം **, size_t);


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

സ്ഥിതം പൂർണ്ണസംഖ്യ
dangerous_locale(ശൂന്യം) {
	അക്ഷരം	*loc;

	loc = nl_langinfo(CODESET);
	തിരികെ strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
grow_dst(അക്ഷരം **dst, size_t *sz, size_t maxsz, അക്ഷരം **dp, size_t need)
{
	അക്ഷരം	*tp;
	size_t	 tsz;

	എങ്കിൽ (*dp + need < *dst + *sz)
		തിരികെ 0;
	tsz = *sz + 128;
	എങ്കിൽ (tsz > maxsz)
		tsz = maxsz;
	എങ്കിൽ ((tp = recallocarray(*dst, *sz, tsz, 1)) == ശൂന്യ)
		തിരികെ -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	തിരികെ 0;
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

പൂർണ്ണസംഖ്യ
vasnmprintf(അക്ഷരം **str, size_t maxsz, പൂർണ്ണസംഖ്യ *wp, സ്ഥിരം അക്ഷരം *fmt, va_list ap)
{
	അക്ഷരം	*src;	/* Source string returned from vasprintf. */
	അക്ഷരം	*sp;	/* Pointer into src. */
	അക്ഷരം	*dst;	/* Destination string to be returned. */
	അക്ഷരം	*dp;	/* Pointer into dst. */
	അക്ഷരം	*tp;	/* Temporary pointer for dst. */
	size_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	പൂർണ്ണസംഖ്യ	 len;	/* Number of bytes in the character at sp. */
	പൂർണ്ണസംഖ്യ	 ret;	/* Number of bytes needed to format src. */
	പൂർണ്ണസംഖ്യ	 width;	/* Display width of the character wc. */
	പൂർണ്ണസംഖ്യ	 total_width, max_width, print;

	src = ശൂന്യ;
	എങ്കിൽ ((ret = vasprintf(&src, fmt, ap)) <= 0)
		പോകുക fail;

	sz = strlen(src) + 1;
	എങ്കിൽ ((dst = malloc(sz)) == ശൂന്യ) {
		സ്വതന്ത്രം(src);
		ret = -1;
		പോകുക fail;
	}

	എങ്കിൽ (maxsz > INT_MAX)
		maxsz = INT_MAX;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == ശൂന്യ ? INT_MAX : *wp;
	ആകുമ്പോൾ (*sp != '\0') {
		എങ്കിൽ ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(ശൂന്യം)mbtowc(ശൂന്യ, ശൂന്യ, MB_CUR_MAX);
			എങ്കിൽ (dangerous_locale()) {
				ret = -1;
				നിർത്തുക;
			}
			len = 1;
			width = -1;
		} അല്ലെങ്കിൽ എങ്കിൽ (wp == ശൂന്യ &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			നിർത്തുക;
		}

		/* Valid, printable character. */

		എങ്കിൽ (width >= 0) {
			എങ്കിൽ (print && (dp - dst >= (പൂർണ്ണസംഖ്യ)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			എങ്കിൽ (print) {
				എങ്കിൽ (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					നിർത്തുക;
				}
				total_width += width;
				memcpy(dp, sp, len);
				dp += len;
			}
			sp += len;
			എങ്കിൽ (ret >= 0)
				ret += len;
			തുടരുക;
		}

		/* Escaping required. */

		ആകുമ്പോൾ (len > 0) {
			എങ്കിൽ (print && (dp - dst >= (പൂർണ്ണസംഖ്യ)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			എങ്കിൽ (print) {
				എങ്കിൽ (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					നിർത്തുക;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} അല്ലെങ്കിൽ
				width = 4;
			len--;
			sp++;
			എങ്കിൽ (ret >= 0)
				ret += width;
		}
		എങ്കിൽ (len > 0)
			നിർത്തുക;
	}
	സ്വതന്ത്രം(src);
	*dp = '\0';
	*str = dst;
	എങ്കിൽ (wp != ശൂന്യ)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	എങ്കിൽ (ret < (പൂർണ്ണസംഖ്യ)maxsz && !print)
		ret = -1;
	തിരികെ ret;

fail:
	എങ്കിൽ (wp != ശൂന്യ)
		*wp = 0;
	എങ്കിൽ (ret == 0) {
		*str = src;
		തിരികെ 0;
	} അല്ലെങ്കിൽ {
		*str = ശൂന്യ;
		തിരികെ -1;
	}
}

പൂർണ്ണസംഖ്യ
snmprintf(അക്ഷരം *str, size_t sz, പൂർണ്ണസംഖ്യ *wp, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list	 ap;
	അക്ഷരം	*cp = ശൂന്യ;
	പൂർണ്ണസംഖ്യ	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	എങ്കിൽ (cp != ശൂന്യ) {
		(ശൂന്യം)strlcpy(str, cp, sz);
		സ്വതന്ത്രം(cp);
	} അല്ലെങ്കിൽ
		*str = '\0';
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
asmprintf(അക്ഷരം **outp, size_t sz, പൂർണ്ണസംഖ്യ *wp, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list	 ap;
	പൂർണ്ണസംഖ്യ	 ret;

	*outp = ശൂന്യ;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	തിരികെ ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

പൂർണ്ണസംഖ്യ
vfmprintf(FILE *stream, സ്ഥിരം അക്ഷരം *fmt, va_list ap)
{
	അക്ഷരം	*str = ശൂന്യ;
	പൂർണ്ണസംഖ്യ	 ret;

	എങ്കിൽ ((ret = vasnmprintf(&str, INT_MAX, ശൂന്യ, fmt, ap)) < 0) {
		സ്വതന്ത്രം(str);
		തിരികെ -1;
	}
	എങ്കിൽ (fputs(str, stream) == EOF)
		ret = -1;
	സ്വതന്ത്രം(str);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
fmprintf(FILE *stream, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list	 ap;
	പൂർണ്ണസംഖ്യ	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	va_end(ap);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
mprintf(സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list	 ap;
	പൂർണ്ണസംഖ്യ	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	തിരികെ ret;
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
ശൂന്യം
msetlocale(ശൂന്യം)
{
	സ്ഥിരം അക്ഷരം *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", ശൂന്യ };
	അക്ഷരം *cp;
	പൂർണ്ണസംഖ്യ i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	വേണ്ടി (i = 0; vars[i] != ശൂന്യ; i++) {
		എങ്കിൽ ((cp = getenv(vars[i])) == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			നിർത്തുക;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		എങ്കിൽ ((strcasestr(cp, "UTF-8") != ശൂന്യ ||
		    strcasestr(cp, "UTF8") != ശൂന്യ) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != ശൂന്യ ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != ശൂന്യ))
			തിരികെ;
		setlocale(LC_CTYPE, "C");
		തിരികെ;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
