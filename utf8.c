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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#నిర్వచితమైతే HAVE_LANGINFO_H
# include <langinfo.h>
#అయితే_ముగింపు
#అన్తర్భావ <limits.h>
#అన్తర్భావ <locale.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#ఒకవేళ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_WCHAR_H
# include <wchar.h>
#అయితే_ముగింపు

#అన్తర్భావ "utf8.h"

స్థిర పూర్ణాంకం	 dangerous_locale(శూన్య);
స్థిర పూర్ణాంకం	 grow_dst(అక్షరం **, కొలత_t *, కొలత_t, అక్షరం **, కొలత_t);


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

స్థిర పూర్ణాంకం
dangerous_locale(శూన్య) {
	అక్షరం	*loc;

	loc = nl_langinfo(CODESET);
	తిరిగి strcmp(loc, "UTF-8") != 0 &&
	    strcmp(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    strcmp(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    strcmp(loc, "ISO8859-1") != 0 &&		/* AIX */
	    strcmp(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    strcmp(loc, "") != 0;			/* Solaris 6 */
}

స్థిర పూర్ణాంకం
grow_dst(అక్షరం **dst, కొలత_t *sz, కొలత_t maxsz, అక్షరం **dp, కొలత_t need)
{
	అక్షరం	*tp;
	కొలత_t	 tsz;

	ఒకవేళ (*dp + need < *dst + *sz)
		తిరిగి 0;
	tsz = *sz + 128;
	ఒకవేళ (tsz > maxsz)
		tsz = maxsz;
	ఒకవేళ ((tp = recallocarray(*dst, *sz, tsz, 1)) == ఖాళీ)
		తిరిగి -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	తిరిగి 0;
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

పూర్ణాంకం
vasnmprintf(అక్షరం **str, కొలత_t maxsz, పూర్ణాంకం *wp, స్థిరరాశి అక్షరం *fmt, va_list ap)
{
	అక్షరం	*src;	/* Source string returned from vasprintf. */
	అక్షరం	*sp;	/* Pointer into src. */
	అక్షరం	*dst;	/* Destination string to be returned. */
	అక్షరం	*dp;	/* Pointer into dst. */
	అక్షరం	*tp;	/* Temporary pointer for dst. */
	కొలత_t	 sz;	/* Number of bytes allocated for dst. */
	wchar_t	 wc;	/* Wide character at sp. */
	పూర్ణాంకం	 len;	/* Number of bytes in the character at sp. */
	పూర్ణాంకం	 ret;	/* Number of bytes needed to format src. */
	పూర్ణాంకం	 వెడల్పు;	/* Display width of the character wc. */
	పూర్ణాంకం	 మొత్తం_వెడల్పు, max_వెడల్పు, print;

	src = ఖాళీ;
	ఒకవేళ ((ret = vasprintf(&src, fmt, ap)) <= 0)
		వెళ్ళు fail;

	sz = అక్షరశ్రేణి_పొడవు(src) + 1;
	ఒకవేళ ((dst = జ్ఞాపకం_ఇవ్వు(sz)) == ఖాళీ) {
		విడుదల(src);
		ret = -1;
		వెళ్ళు fail;
	}

	ఒకవేళ (maxsz > గరిష్ఠ_పూర్ణాంకం)
		maxsz = గరిష్ఠ_పూర్ణాంకం;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	మొత్తం_వెడల్పు = 0;
	max_వెడల్పు = wp == ఖాళీ ? గరిష్ఠ_పూర్ణాంకం : *wp;
	అయితే (*sp != '\0') {
		ఒకవేళ ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(శూన్య)mbtowc(ఖాళీ, ఖాళీ, MB_CUR_MAX);
			ఒకవేళ (dangerous_locale()) {
				ret = -1;
				ఆపు;
			}
			len = 1;
			వెడల్పు = -1;
		} లేకపోతే ఒకవేళ (wp == ఖాళీ &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			వెడల్పు = 0;
		} లేకపోతే ఒకవేళ ((వెడల్పు = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			ఆపు;
		}

		/* Valid, printable character. */

		ఒకవేళ (వెడల్పు >= 0) {
			ఒకవేళ (print && (dp - dst >= (పూర్ణాంకం)maxsz - len ||
			    మొత్తం_వెడల్పు > max_వెడల్పు - వెడల్పు))
				print = 0;
			ఒకవేళ (print) {
				ఒకవేళ (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					ఆపు;
				}
				మొత్తం_వెడల్పు += వెడల్పు;
				జ్ఞాపకం_నకలు(dp, sp, len);
				dp += len;
			}
			sp += len;
			ఒకవేళ (ret >= 0)
				ret += len;
			కొనసాగు;
		}

		/* Escaping required. */

		అయితే (len > 0) {
			ఒకవేళ (print && (dp - dst >= (పూర్ణాంకం)maxsz - 4 ||
			    మొత్తం_వెడల్పు > max_వెడల్పు - 4))
				print = 0;
			ఒకవేళ (print) {
				ఒకవేళ (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					ఆపు;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				వెడల్పు = tp - dp;
				మొత్తం_వెడల్పు += వెడల్పు;
				dp = tp;
			} లేకపోతే
				వెడల్పు = 4;
			len--;
			sp++;
			ఒకవేళ (ret >= 0)
				ret += వెడల్పు;
		}
		ఒకవేళ (len > 0)
			ఆపు;
	}
	విడుదల(src);
	*dp = '\0';
	*str = dst;
	ఒకవేళ (wp != ఖాళీ)
		*wp = మొత్తం_వెడల్పు;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	ఒకవేళ (ret < (పూర్ణాంకం)maxsz && !print)
		ret = -1;
	తిరిగి ret;

fail:
	ఒకవేళ (wp != ఖాళీ)
		*wp = 0;
	ఒకవేళ (ret == 0) {
		*str = src;
		తిరిగి 0;
	} లేకపోతే {
		*str = ఖాళీ;
		తిరిగి -1;
	}
}

పూర్ణాంకం
snmprintf(అక్షరం *str, కొలత_t sz, పూర్ణాంకం *wp, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list	 ap;
	అక్షరం	*cp = ఖాళీ;
	పూర్ణాంకం	 ret;

	va_start(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	va_end(ap);
	ఒకవేళ (cp != ఖాళీ) {
		(శూన్య)strlcpy(str, cp, sz);
		విడుదల(cp);
	} లేకపోతే
		*str = '\0';
	తిరిగి ret;
}

పూర్ణాంకం
asmprintf(అక్షరం **outp, కొలత_t sz, పూర్ణాంకం *wp, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list	 ap;
	పూర్ణాంకం	 ret;

	*outp = ఖాళీ;
	va_start(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	va_end(ap);

	తిరిగి ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

పూర్ణాంకం
vfmprintf(FILE *ప్రవాహం, స్థిరరాశి అక్షరం *fmt, va_list ap)
{
	అక్షరం	*str = ఖాళీ;
	పూర్ణాంకం	 ret;

	ఒకవేళ ((ret = vasnmprintf(&str, గరిష్ఠ_పూర్ణాంకం, ఖాళీ, fmt, ap)) < 0) {
		విడుదల(str);
		తిరిగి -1;
	}
	ఒకవేళ (fputs(str, ప్రవాహం) == EOF)
		ret = -1;
	విడుదల(str);
	తిరిగి ret;
}

పూర్ణాంకం
fmprintf(FILE *ప్రవాహం, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list	 ap;
	పూర్ణాంకం	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(ప్రవాహం, fmt, ap);
	va_end(ap);
	తిరిగి ret;
}

పూర్ణాంకం
mprintf(స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list	 ap;
	పూర్ణాంకం	 ret;

	va_start(ap, fmt);
	ret = vfmprintf(stdout, fmt, ap);
	va_end(ap);
	తిరిగి ret;
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
శూన్య
msetlocale(శూన్య)
{
	స్థిరరాశి అక్షరం *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", ఖాళీ };
	అక్షరం *cp;
	పూర్ణాంకం i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	కొరకు (i = 0; vars[i] != ఖాళీ; i++) {
		ఒకవేళ ((cp = getenv(vars[i])) == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			ఆపు;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		ఒకవేళ ((strcasestr(cp, "UTF-8") != ఖాళీ ||
		    strcasestr(cp, "UTF8") != ఖాళీ) &&
		    (setlocale(LC_CTYPE, "C.UTF-8") != ఖాళీ ||
		    setlocale(LC_CTYPE, "POSIX.UTF-8") != ఖాళీ))
			తిరిగి;
		setlocale(LC_CTYPE, "C");
		తిరిగి;
	}
	/* We can handle this locale */
	setlocale(LC_CTYPE, "");
}
