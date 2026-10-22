/*	$OpenBSD: fmt_scaled.c,v 1.25 2026/06/06 23:53:59 djm Exp $	*/

/*
 * Copyright (c) 2001, 2002, 2003 Ian F. Darwin.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libutil/fmt_scaled.c */

/*
 * fmt_scaled: Format numbers scaled for human comprehension
 * scan_scaled: Scan numbers in this format.
 *
 * "Human-readable" output uses 4 digits max, and puts a unit suffix at
 * the end.  Makes output compact and easy-to-read esp. on huge disks.
 * Formatting code was originally in OpenBSD "df", converted to library routine.
 * Scanning code written for OpenBSD libutil.
 */

#अन्तर्भाव "includes.h"

#ifndef HAVE_FMT_SCALED

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <ctype.h>
#अन्तर्भाव <limits.h>

प्रकारव्याख्या गणना {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
स्थिर स्थिरांक unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
स्थिर स्थिरांक अक्षर scale_chars[] = "BKMGTPE";
स्थिर स्थिरांक दीर्घ दीर्घ scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#define	SCALE_LENGTH (आकार(units)/आकार(units[0]))

#define MAX_DIGITS (SCALE_LENGTH * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
पूर्णांक
scan_scaled(अक्षर *scaled, दीर्घ दीर्घ *result)
{
	अक्षर *p = scaled;
	पूर्णांक sign = 0;
	अचिन्हित पूर्णांक i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	दीर्घ दीर्घ scale_fact = 1, whole = 0, fpart = 0;

	/* Skip leading whitespace */
	पर्यंत (isascii((अचिन्हित अक्षर)*p) && है_खाली((अचिन्हित अक्षर)*p))
		++p;

	/* Then at most one leading + or - */
	पर्यंत (*p == '-' || *p == '+') {
		जर (*p == '-') {
			जर (sign) {
				त्रुटि_सं = EINVAL;
				परत -1;
			}
			sign = -1;
			++p;
		} अन्यथा जर (*p == '+') {
			जर (sign) {
				त्रुटि_सं = EINVAL;
				परत -1;
			}
			sign = +1;
			++p;
		}
	}

	/* Main loop: Scan digits, find decimal point, if present.
	 * We don't allow exponentials, so no scientific notation
	 * (but note that E for Exa might look like e to some!).
	 * Advance 'p' to end, to get scale factor.
	 */
	साठी (; isascii((अचिन्हित अक्षर)*p) &&
	    (है_अंक((अचिन्हित अक्षर)*p) || *p=='.'); ++p) {
		जर (*p == '.') {
			जर (fract_digits > 0) {	/* oops, more than one '.' */
				त्रुटि_सं = EINVAL;
				परत -1;
			}
			fract_digits = 1;
			सुरूठेवा;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		जर (fract_digits > 0) {
			जर (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				सुरूठेवा;
			fract_digits++;		/* for later scaling */
			जर (fpart > LLONG_MAX / 10) {
				त्रुटि_सं = दुस्फल;
				परत -1;
			}
			fpart *= 10;
			जर (i > LLONG_MAX - fpart) {
				त्रुटि_सं = दुस्फल;
				परत -1;
			}
			fpart += i;
		} अन्यथा {				/* normal digit */
			जर (++ndigits >= MAX_DIGITS) {
				त्रुटि_सं = दुस्फल;
				परत -1;
			}
			जर (whole > LLONG_MAX / 10) {
				त्रुटि_सं = दुस्फल;
				परत -1;
			}
			whole *= 10;
			जर (i > LLONG_MAX - whole) {
				त्रुटि_सं = दुस्फल;
				परत -1;
			}
			whole += i;
		}
	}

	जर (sign)
		whole *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	जर (!*p) {
		*result = whole;
		परत 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	साठी (i = 0; i < SCALE_LENGTH; i++) {

		/* Are we there yet? */
		जर (*p == scale_chars[i] ||
			*p == छोटे((अचिन्हित अक्षर)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			जर (है_अक्षर_अंक((अचिन्हित अक्षर)*(p+1))) {
				त्रुटि_सं = EINVAL;
				परत -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			जर (whole > LLONG_MAX / scale_fact ||
			    whole < LLONG_MIN / scale_fact) {
				त्रुटि_सं = दुस्फल;
				परत -1;
			}

			/* scale whole part */
			whole *= scale_fact;

			/*
			 * Scale fractional part: compute
			 *   fpart * scale_fact / 10^(fract_digits-1)
			 * without intermediate overflow. scale_fact is 1024^i,
			 * i.e. a power of 1024 = 2^10. Interleave
			 * multiply-by-1024 with divide-by-10 so the running
			 * value stays within long long range while preserving
			 * precision.
			 */
			muls = i;
			divs = fract_digits > 0 ?  fract_digits - 1 : 0;
			पर्यंत (muls > 0 && divs > 0) {
				जर (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} अन्यथा {
					fpart /= 10;
					divs--;
				}
			}
			पर्यंत (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			पर्यंत (divs > 0) {
				fpart /= 10;
				divs--;
			}
			जर (sign == -1)
				whole -= fpart;
			अन्यथा
				whole += fpart;
			*result = whole;
			परत 0;
		}
	}

	/* Invalid unit or character */
	त्रुटि_सं = EINVAL;
	परत -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
पूर्णांक
fmt_scaled(दीर्घ दीर्घ संख्या, अक्षर *result)
{
	दीर्घ दीर्घ abval, fract = 0;
	अचिन्हित पूर्णांक i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	जर (संख्या == LLONG_MIN) {
		त्रुटि_सं = दुस्फल;
		परत -1;
	}

	abval = llabs(संख्या);

	/* Also check for numbers that are just too darned big to format. */
	जर (abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		त्रुटि_सं = दुस्फल;
		परत -1;
	}

	/* scale whole part; get unscaled fraction */
	साठी (i = 0; i < SCALE_LENGTH; i++) {
		जर (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			संख्या /= scale_factors[i];
			जर (i > 0)
				fract /= scale_factors[i - 1];
			थांबा;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	जर (fract >= 10) {
		जर (संख्या >= 0)
			संख्या++;
		अन्यथा
			संख्या--;
		fract = 0;
	} अन्यथा जर (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	जर (संख्या == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	अन्यथा जर (unit == NONE || संख्या >= 100 || संख्या <= -100) {
		जर (fract >= 5) {
			जर (संख्या >= 0)
				संख्या++;
			अन्यथा
				संख्या--;
		}
		(शून्य)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			संख्या, scale_chars[unit]);
	} अन्यथा
		(शून्य)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			संख्या, fract, scale_chars[unit]);

	परत 0;
}

#ifdef	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	अक्षर *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	दीर्घ दीर्घ ninput = 10483892, result;

	जर (scan_scaled(cinput, &result) == 0)
		म_लिखो("\"%s\" -> %lld\n", cinput, result);
	अन्यथा
		लिखो_त्रुटि(cinput);

	जर (fmt_scaled(ninput, buf) == 0)
		म_लिखो("%lld -> \"%s\"\n", ninput, buf);
	अन्यथा
		ख_लिखो(मानक_त्रुटि, "%lld invalid (%s)\n", ninput, म_त्रुटि(त्रुटि_सं));

	परत 0;
}
#endif

#endif /* HAVE_FMT_SCALED */
