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
#जर defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif
#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif

#अन्तर्भाव "utf8.h"

स्थिर पूर्णांक	 dangerous_locale(शून्य);
स्थिर पूर्णांक	 grow_dst(अक्षर **, माप_प्रकार *, माप_प्रकार, अक्षर **, माप_प्रकार);


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

स्थिर पूर्णांक
dangerous_locale(शून्य) {
	अक्षर	*loc;

	loc = nl_langinfo(CODESET);
	परत म_भेद(loc, "UTF-8") != 0 &&
	    म_भेद(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    म_भेद(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    म_भेद(loc, "ISO8859-1") != 0 &&		/* AIX */
	    म_भेद(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    म_भेद(loc, "") != 0;			/* Solaris 6 */
}

स्थिर पूर्णांक
grow_dst(अक्षर **dst, माप_प्रकार *sz, माप_प्रकार maxsz, अक्षर **dp, माप_प्रकार need)
{
	अक्षर	*tp;
	माप_प्रकार	 tsz;

	जर (*dp + need < *dst + *sz)
		परत 0;
	tsz = *sz + 128;
	जर (tsz > maxsz)
		tsz = maxsz;
	जर ((tp = recallocarray(*dst, *sz, tsz, 1)) == रिक्त)
		परत -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	परत 0;
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

पूर्णांक
vasnmprintf(अक्षर **str, माप_प्रकार maxsz, पूर्णांक *wp, स्थिरांक अक्षर *fmt, बहु_सूची ap)
{
	अक्षर	*src;	/* Source string returned from vasprintf. */
	अक्षर	*sp;	/* Pointer into src. */
	अक्षर	*dst;	/* Destination string to be returned. */
	अक्षर	*dp;	/* Pointer into dst. */
	अक्षर	*tp;	/* Temporary pointer for dst. */
	माप_प्रकार	 sz;	/* Number of bytes allocated for dst. */
	ब_अक्षर_प्रकार	 wc;	/* Wide character at sp. */
	पूर्णांक	 len;	/* Number of bytes in the character at sp. */
	पूर्णांक	 ret;	/* Number of bytes needed to format src. */
	पूर्णांक	 width;	/* Display width of the character wc. */
	पूर्णांक	 total_width, max_width, print;

	src = रिक्त;
	जर ((ret = vasprintf(&src, fmt, ap)) <= 0)
		जा fail;

	sz = म_माप(src) + 1;
	जर ((dst = दो_स्मृति(sz)) == रिक्त) {
		मुक्त(src);
		ret = -1;
		जा fail;
	}

	जर (maxsz > पूर्णांक_उच्च)
		maxsz = पूर्णांक_उच्च;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	total_width = 0;
	max_width = wp == रिक्त ? पूर्णांक_उच्च : *wp;
	पर्यंत (*sp != '\0') {
		जर ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(शून्य)mbtowc(रिक्त, रिक्त, MB_CUR_MAX);
			जर (dangerous_locale()) {
				ret = -1;
				थांबा;
			}
			len = 1;
			width = -1;
		} अन्यथा जर (wp == रिक्त &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} अन्यथा जर ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			थांबा;
		}

		/* Valid, printable character. */

		जर (width >= 0) {
			जर (print && (dp - dst >= (पूर्णांक)maxsz - len ||
			    total_width > max_width - width))
				print = 0;
			जर (print) {
				जर (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					थांबा;
				}
				total_width += width;
				स_नकल(dp, sp, len);
				dp += len;
			}
			sp += len;
			जर (ret >= 0)
				ret += len;
			सुरूठेवा;
		}

		/* Escaping required. */

		पर्यंत (len > 0) {
			जर (print && (dp - dst >= (पूर्णांक)maxsz - 4 ||
			    total_width > max_width - 4))
				print = 0;
			जर (print) {
				जर (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					थांबा;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				total_width += width;
				dp = tp;
			} अन्यथा
				width = 4;
			len--;
			sp++;
			जर (ret >= 0)
				ret += width;
		}
		जर (len > 0)
			थांबा;
	}
	मुक्त(src);
	*dp = '\0';
	*str = dst;
	जर (wp != रिक्त)
		*wp = total_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	जर (ret < (पूर्णांक)maxsz && !print)
		ret = -1;
	परत ret;

fail:
	जर (wp != रिक्त)
		*wp = 0;
	जर (ret == 0) {
		*str = src;
		परत 0;
	} अन्यथा {
		*str = रिक्त;
		परत -1;
	}
}

पूर्णांक
snmprintf(अक्षर *str, माप_प्रकार sz, पूर्णांक *wp, स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची	 ap;
	अक्षर	*cp = रिक्त;
	पूर्णांक	 ret;

	बहु_शुरू(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	बहु_पूर्ण(ap);
	जर (cp != रिक्त) {
		(शून्य)strlcpy(str, cp, sz);
		मुक्त(cp);
	} अन्यथा
		*str = '\0';
	परत ret;
}

पूर्णांक
asmprintf(अक्षर **outp, माप_प्रकार sz, पूर्णांक *wp, स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची	 ap;
	पूर्णांक	 ret;

	*outp = रिक्त;
	बहु_शुरू(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	बहु_पूर्ण(ap);

	परत ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

पूर्णांक
vfmprintf(खाता *stream, स्थिरांक अक्षर *fmt, बहु_सूची ap)
{
	अक्षर	*str = रिक्त;
	पूर्णांक	 ret;

	जर ((ret = vasnmprintf(&str, पूर्णांक_उच्च, रिक्त, fmt, ap)) < 0) {
		मुक्त(str);
		परत -1;
	}
	जर (ख_माला_दो(str, stream) == खातापूर्ण)
		ret = -1;
	मुक्त(str);
	परत ret;
}

पूर्णांक
fmprintf(खाता *stream, स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची	 ap;
	पूर्णांक	 ret;

	बहु_शुरू(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	बहु_पूर्ण(ap);
	परत ret;
}

पूर्णांक
mprintf(स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची	 ap;
	पूर्णांक	 ret;

	बहु_शुरू(ap, fmt);
	ret = vfmprintf(मानक_निकास, fmt, ap);
	बहु_पूर्ण(ap);
	परत ret;
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
	स्थिरांक अक्षर *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", रिक्त };
	अक्षर *cp;
	पूर्णांक i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	साठी (i = 0; vars[i] != रिक्त; i++) {
		जर ((cp = दो_पर्या(vars[i])) == रिक्त)
			सुरूठेवा;
		जर (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			थांबा;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		जर ((strcasestr(cp, "UTF-8") != रिक्त ||
		    strcasestr(cp, "UTF8") != रिक्त) &&
		    (रखो_क्षेत्र(LC_CTYPE, "C.UTF-8") != रिक्त ||
		    रखो_क्षेत्र(LC_CTYPE, "POSIX.UTF-8") != रिक्त))
			परत;
		रखो_क्षेत्र(LC_CTYPE, "C");
		परत;
	}
	/* We can handle this locale */
	रखो_क्षेत्र(LC_CTYPE, "");
}
