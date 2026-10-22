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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LANGINFO_H
# include <langinfo.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <locale.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಆದರೆ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_WCHAR_H
# include <wchar.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "utf8.h"

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 dangerous_locale(ಶೂನ್ಯ);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ	 grow_dst(ಅಕ್ಷರ **, ಗಾತ್ರ_t *, ಗಾತ್ರ_t, ಅಕ್ಷರ **, ಗಾತ್ರ_t);


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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
dangerous_locale(ಶೂನ್ಯ) {
	ಅಕ್ಷರ	*loc;

	loc = nl_langinfo(CODESET);
	ಹಿಂತಿರುಗಿ strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
grow_dst(ಅಕ್ಷರ **dst, ಗಾತ್ರ_t *sz, ಗಾತ್ರ_t maxsz, ಅಕ್ಷರ **dp, ಗಾತ್ರ_t need)
{
	ಅಕ್ಷರ	*tp;
	ಗಾತ್ರ_t	 tsz;

	ಆದರೆ (*dp + need < *dst + *sz)
		ಹಿಂತಿರುಗಿ 0;
	tsz = *sz + 128;
	ಆದರೆ (tsz > maxsz)
		tsz = maxsz;
	ಆದರೆ ((tp = recallocarray(*dst, *sz, tsz, 1)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	ಹಿಂತಿರುಗಿ 0;
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

ಪೂರ್ಣಾಂಕ
vasnmprintf(ಅಕ್ಷರ **str, ಗಾತ್ರ_t maxsz, ಪೂರ್ಣಾಂಕ *wp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, va_list ap)
{
	ಅಕ್ಷರ	*src;	/* Source string returned from vasprintf. */
	ಅಕ್ಷರ	*sp;	/* Pointer into src. */
	ಅಕ್ಷರ	*dst;	/* Destination string to be returned. */
	ಅಕ್ಷರ	*dp;	/* Pointer into dst. */
	ಅಕ್ಷರ	*tp;	/* Temporary pointer for dst. */
	ಗಾತ್ರ_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	ಪೂರ್ಣಾಂಕ	 len;	/* Number of bytes in the character at sp. */
	ಪೂರ್ಣಾಂಕ	 ret;	/* Number of bytes needed to format src. */
	ಪೂರ್ಣಾಂಕ	 ಅಗಲ;	/* Display width of the character wc. */
	ಪೂರ್ಣಾಂಕ	 ಒಟ್ಟು_ಅಗಲ, max_ಅಗಲ, print;

	src = ಖಾಲಿ;
	ಆದರೆ ((ret = vasprintf(&src, fmt, ap)) <= 0)
		ಹೋಗು fail;

	sz = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(src) + 1;
	ಆದರೆ ((dst = ಸ್ಮರಣೆ_ಕೊಡು(sz)) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(src);
		ret = -1;
		ಹೋಗು fail;
	}

	ಆದರೆ (maxsz > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		maxsz = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	ಒಟ್ಟು_ಅಗಲ = 0;
	max_ಅಗಲ = wp == ಖಾಲಿ ? ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ : *wp;
	ಆಗ (*sp != '\0') {
		ಆದರೆ ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(ಶೂನ್ಯ)mbtowc(ಖಾಲಿ, ಖಾಲಿ, MB_CUR_MAX);
			ಆದರೆ (dangerous_locale()) {
				ret = -1;
				ನಿಲ್ಲಿಸು;
			}
			len = 1;
			ಅಗಲ = -1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (wp == ಖಾಲಿ &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			ಅಗಲ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ಅಗಲ = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			ನಿಲ್ಲಿಸು;
		}

		/* Valid, printable character. */

		ಆದರೆ (ಅಗಲ >= 0) {
			ಆದರೆ (print && (dp - dst >= (ಪೂರ್ಣಾಂಕ)maxsz - len ||
			    ಒಟ್ಟು_ಅಗಲ > max_ಅಗಲ - ಅಗಲ))
				print = 0;
			ಆದರೆ (print) {
				ಆದರೆ (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					ನಿಲ್ಲಿಸು;
				}
				ಒಟ್ಟು_ಅಗಲ += ಅಗಲ;
				ಸ್ಮರಣೆ_ನಕಲು(dp, sp, len);
				dp += len;
			}
			sp += len;
			ಆದರೆ (ret >= 0)
				ret += len;
			ಮುಂದುವರಿ;
		}

		/* Escaping required. */

		ಆಗ (len > 0) {
			ಆದರೆ (print && (dp - dst >= (ಪೂರ್ಣಾಂಕ)maxsz - 4 ||
			    ಒಟ್ಟು_ಅಗಲ > max_ಅಗಲ - 4))
				print = 0;
			ಆದರೆ (print) {
				ಆದರೆ (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					ನಿಲ್ಲಿಸು;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				ಅಗಲ = tp - dp;
				ಒಟ್ಟು_ಅಗಲ += ಅಗಲ;
				dp = tp;
			} ಇಲ್ಲದಿದ್ದರೆ
				ಅಗಲ = 4;
			len--;
			sp++;
			ಆದರೆ (ret >= 0)
				ret += ಅಗಲ;
		}
		ಆದರೆ (len > 0)
			ನಿಲ್ಲಿಸು;
	}
	ಬಿಡುಗಡೆ(src);
	*dp = '\0';
	*str = dst;
	ಆದರೆ (wp != ಖಾಲಿ)
		*wp = ಒಟ್ಟು_ಅಗಲ;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	ಆದರೆ (ret < (ಪೂರ್ಣಾಂಕ)maxsz && !print)
		ret = -1;
	ಹಿಂತಿರುಗಿ ret;

fail:
	ಆದರೆ (wp != ಖಾಲಿ)
		*wp = 0;
	ಆದರೆ (ret == 0) {
		*str = src;
		ಹಿಂತಿರುಗಿ 0;
	} ಇಲ್ಲದಿದ್ದರೆ {
		*str = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಪೂರ್ಣಾಂಕ
snmprintf(ಅಕ್ಷರ *str, ಗಾತ್ರ_t sz, ಪೂರ್ಣಾಂಕ *wp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list	 ap;
	ಅಕ್ಷರ	*cp = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	ಆದರೆ (cp != ಖಾಲಿ) {
		(ಶೂನ್ಯ)strlcpy(str, cp, sz);
		ಬಿಡುಗಡೆ(cp);
	} ಇಲ್ಲದಿದ್ದರೆ
		*str = '\0';
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
asmprintf(ಅಕ್ಷರ **outp, ಗಾತ್ರ_t sz, ಪೂರ್ಣಾಂಕ *wp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list	 ap;
	ಪೂರ್ಣಾಂಕ	 ret;

	*outp = ಖಾಲಿ;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	ಹಿಂತಿರುಗಿ ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

ಪೂರ್ಣಾಂಕ
vfmprintf(FILE *ಹರಿವು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, va_list ap)
{
	ಅಕ್ಷರ	*str = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ	 ret;

	ಆದರೆ ((ret = vasnmprintf(&str, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, ಖಾಲಿ, fmt, ap)) < 0) {
		ಬಿಡುಗಡೆ(str);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (fputs(str, ಹರಿವು) == EOF)
		ret = -1;
	ಬಿಡುಗಡೆ(str);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
fmprintf(FILE *ಹರಿವು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list	 ap;
	ಪೂರ್ಣಾಂಕ	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(ಹರಿವು, fmt, ap);
	va_end(ap);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
mprintf(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list	 ap;
	ಪೂರ್ಣಾಂಕ	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	ಹಿಂತಿರುಗಿ ret;
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
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", ಖಾಲಿ };
	ಅಕ್ಷರ *cp;
	ಪೂರ್ಣಾಂಕ i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	ಗಾಗಿ (i = 0; vars[i] != ಖಾಲಿ; i++) {
		ಆದರೆ ((cp = getenv(vars[i])) == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			ನಿಲ್ಲಿಸು;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		ಆದರೆ ((strcasestr(cp, "UTF-8") != ಖಾಲಿ ||
		    strcasestr(cp, "UTF8") != ಖಾಲಿ) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != ಖಾಲಿ ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != ಖಾಲಿ))
			ಹಿಂತಿರುಗಿ;
		setlocale(LC_CTYPE, "C");
		ಹಿಂತಿರುಗಿ;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
