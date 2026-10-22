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

#समावेश "includes.h"

#समावेश <sys/types.h>
#अगर_घोषित HAVE_LANGINFO_H
# include <langinfo.h>
#पूर्ण_अगर
#समावेश <limits.h>
#समावेश <locale.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#अगर defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_WCHAR_H
# include <wchar.h>
#पूर्ण_अगर

#समावेश "utf8.h"

अटल पूर्णांक	 dangerous_locale(व्योम);
अटल पूर्णांक	 grow_dst(अक्षर **, माप_प्रकार *, माप_प्रकार, अक्षर **, माप_प्रकार);


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

अटल पूर्णांक
dangerous_locale(व्योम) {
	अक्षर	*loc;

	loc = nl_langinfo(CODESET);
	वापस म_भेद(loc, "UTF-8") != 0 &&
	    म_भेद(loc, "US-ASCII") != 0 &&		/* OpenBSD */
	    म_भेद(loc, "ANSI_X3.4-1968") != 0 &&	/* Linux */
	    म_भेद(loc, "ISO8859-1") != 0 &&		/* AIX */
	    म_भेद(loc, "646") != 0 &&			/* Solaris, NetBSD */
	    म_भेद(loc, "") != 0;			/* Solaris 6 */
}

अटल पूर्णांक
grow_dst(अक्षर **dst, माप_प्रकार *sz, माप_प्रकार maxsz, अक्षर **dp, माप_प्रकार need)
{
	अक्षर	*tp;
	माप_प्रकार	 tsz;

	अगर (*dp + need < *dst + *sz)
		वापस 0;
	tsz = *sz + 128;
	अगर (tsz > maxsz)
		tsz = maxsz;
	अगर ((tp = recallocarray(*dst, *sz, tsz, 1)) == शून्य)
		वापस -1;
	*dp = tp + (*dp - *dst);
	*dst = tp;
	*sz = tsz;
	वापस 0;
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
vasnmprintf(अक्षर **str, माप_प्रकार maxsz, पूर्णांक *wp, स्थिर अक्षर *fmt, बहु_सूची ap)
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
	पूर्णांक	 योग_width, max_width, print;

	src = शून्य;
	अगर ((ret = vasprintf(&src, fmt, ap)) <= 0)
		जाओ fail;

	sz = म_माप(src) + 1;
	अगर ((dst = दो_स्मृति(sz)) == शून्य) {
		मुक्त(src);
		ret = -1;
		जाओ fail;
	}

	अगर (maxsz > पूर्णांक_उच्च)
		maxsz = पूर्णांक_उच्च;

	sp = src;
	dp = dst;
	ret = 0;
	print = 1;
	योग_width = 0;
	max_width = wp == शून्य ? पूर्णांक_उच्च : *wp;
	जबतक (*sp != '\0') {
		अगर ((len = mbtowc(&wc, sp, MB_CUR_MAX)) == -1) {
			(व्योम)mbtowc(शून्य, शून्य, MB_CUR_MAX);
			अगर (dangerous_locale()) {
				ret = -1;
				अवरोध;
			}
			len = 1;
			width = -1;
		} अन्यथा अगर (wp == शून्य &&
		    (wc == L'\n' || wc == L'\r' || wc == L'\t')) {
			/*
			 * Don't use width uninitialized; the actual
			 * value doesn't matter because total_width
			 * is only returned for wp != NULL.
			 */
			width = 0;
		} अन्यथा अगर ((width = wcwidth(wc)) == -1 &&
		    dangerous_locale()) {
			ret = -1;
			अवरोध;
		}

		/* Valid, printable character. */

		अगर (width >= 0) {
			अगर (print && (dp - dst >= (पूर्णांक)maxsz - len ||
			    योग_width > max_width - width))
				print = 0;
			अगर (print) {
				अगर (grow_dst(&dst, &sz, maxsz,
				    &dp, len) == -1) {
					ret = -1;
					अवरोध;
				}
				योग_width += width;
				स_नकल(dp, sp, len);
				dp += len;
			}
			sp += len;
			अगर (ret >= 0)
				ret += len;
			जारी;
		}

		/* Escaping required. */

		जबतक (len > 0) {
			अगर (print && (dp - dst >= (पूर्णांक)maxsz - 4 ||
			    योग_width > max_width - 4))
				print = 0;
			अगर (print) {
				अगर (grow_dst(&dst, &sz, maxsz,
				    &dp, 4) == -1) {
					ret = -1;
					अवरोध;
				}
				tp = vis(dp, *sp, VIS_OCTAL | VIS_ALL, 0);
				width = tp - dp;
				योग_width += width;
				dp = tp;
			} अन्यथा
				width = 4;
			len--;
			sp++;
			अगर (ret >= 0)
				ret += width;
		}
		अगर (len > 0)
			अवरोध;
	}
	मुक्त(src);
	*dp = '\0';
	*str = dst;
	अगर (wp != शून्य)
		*wp = योग_width;

	/*
	 * If the string was truncated by the width limit but
	 * would have fit into the size limit, the only sane way
	 * to report the problem is using the return value, such
	 * that the usual idiom "if (ret < 0 || ret >= sz) error"
	 * works as expected.
	 */

	अगर (ret < (पूर्णांक)maxsz && !print)
		ret = -1;
	वापस ret;

fail:
	अगर (wp != शून्य)
		*wp = 0;
	अगर (ret == 0) {
		*str = src;
		वापस 0;
	} अन्यथा {
		*str = शून्य;
		वापस -1;
	}
}

पूर्णांक
snmprintf(अक्षर *str, माप_प्रकार sz, पूर्णांक *wp, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची	 ap;
	अक्षर	*cp = शून्य;
	पूर्णांक	 ret;

	बहु_शुरू(ap, fmt);
	ret = vasnmprintf(&cp, sz, wp, fmt, ap);
	बहु_पूर्ण(ap);
	अगर (cp != शून्य) {
		(व्योम)strlcpy(str, cp, sz);
		मुक्त(cp);
	} अन्यथा
		*str = '\0';
	वापस ret;
}

पूर्णांक
asmprintf(अक्षर **outp, माप_प्रकार sz, पूर्णांक *wp, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची	 ap;
	पूर्णांक	 ret;

	*outp = शून्य;
	बहु_शुरू(ap, fmt);
	ret = vasnmprintf(outp, sz, wp, fmt, ap);
	बहु_पूर्ण(ap);

	वापस ret;
}

/*
 * To stay close to the standard interfaces, the following functions
 * return the number of non-NUL bytes written.
 */

पूर्णांक
vfmprintf(खाता *stream, स्थिर अक्षर *fmt, बहु_सूची ap)
{
	अक्षर	*str = शून्य;
	पूर्णांक	 ret;

	अगर ((ret = vasnmprintf(&str, पूर्णांक_उच्च, शून्य, fmt, ap)) < 0) {
		मुक्त(str);
		वापस -1;
	}
	अगर (ख_माला_दो(str, stream) == खातापूर्ण)
		ret = -1;
	मुक्त(str);
	वापस ret;
}

पूर्णांक
fmprintf(खाता *stream, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची	 ap;
	पूर्णांक	 ret;

	बहु_शुरू(ap, fmt);
	ret = vfmprintf(stream, fmt, ap);
	बहु_पूर्ण(ap);
	वापस ret;
}

पूर्णांक
mprintf(स्थिर अक्षर *fmt, ...)
{
	बहु_सूची	 ap;
	पूर्णांक	 ret;

	बहु_शुरू(ap, fmt);
	ret = vfmprintf(मानक_निकास, fmt, ap);
	बहु_पूर्ण(ap);
	वापस ret;
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
व्योम
msetlocale(व्योम)
{
	स्थिर अक्षर *vars[] = { "LC_ALL", "LC_CTYPE", "LANG", शून्य };
	अक्षर *cp;
	पूर्णांक i;

	/*
	 * We can't yet cope with dotless/dotted I in Turkic locales,
	 * so fall back to the C locale for these.
	 */
	क्रम (i = 0; vars[i] != शून्य; i++) {
		अगर ((cp = दो_पर्या(vars[i])) == शून्य)
			जारी;
		अगर (strncasecmp(cp, "tr", 2) != 0 &&
		    strncasecmp(cp, "crh", 3) != 0 &&
		    strncasecmp(cp, "az", 2) != 0)
			अवरोध;
		/*
		 * If we're in a UTF-8 locale then prefer to use
		 * the C.UTF-8 locale (or equivalent) if it exists.
		 */
		अगर ((strcasestr(cp, "UTF-8") != शून्य ||
		    strcasestr(cp, "UTF8") != शून्य) &&
		    (रखो_क्षेत्र(LC_CTYPE, "C.UTF-8") != शून्य ||
		    रखो_क्षेत्र(LC_CTYPE, "POSIX.UTF-8") != शून्य))
			वापस;
		रखो_क्षेत्र(LC_CTYPE, "C");
		वापस;
	}
	/* We can handle this locale */
	रखो_क्षेत्र(LC_CTYPE, "");
}
