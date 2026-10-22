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

प्रकारनिर्देश गणना {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
स्थिर ध्रुव unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
स्थिर ध्रुव वर्ण scale_chars[] = "BKMGTPE";
स्थिर ध्रुव long long scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#define	SCALE_LENGTH (परिमाण(units)/परिमाण(units[0]))

#define MAX_DIGITS (SCALE_LENGTH * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
पूर्णाङ्क
scan_scaled(वर्ण *scaled, long long *result)
{
	वर्ण *p = scaled;
	पूर्णाङ्क sign = 0;
	unsigned पूर्णाङ्क i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	long long scale_fact = 1, whole = 0, fpart = 0;

	/* Skip leading whitespace */
	जाव (isascii((unsigned वर्ण)*p) && isspace((unsigned वर्ण)*p))
		++p;

	/* Then at most one leading + or - */
	जाव (*p == '-' || *p == '+') {
		जइ (*p == '-') {
			जइ (sign) {
				errno = EINVAL;
				प्रत्यागम -1;
			}
			sign = -1;
			++p;
		} अण्णहा जइ (*p == '+') {
			जइ (sign) {
				errno = EINVAL;
				प्रत्यागम -1;
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
	प्रति (; isascii((unsigned वर्ण)*p) &&
	    (isdigit((unsigned वर्ण)*p) || *p=='.'); ++p) {
		जइ (*p == '.') {
			जइ (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				प्रत्यागम -1;
			}
			fract_digits = 1;
			अनुवर्त;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		जइ (fract_digits > 0) {
			जइ (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				अनुवर्त;
			fract_digits++;		/* for later scaling */
			जइ (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				प्रत्यागम -1;
			}
			fpart *= 10;
			जइ (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				प्रत्यागम -1;
			}
			fpart += i;
		} अण्णहा {				/* normal digit */
			जइ (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				प्रत्यागम -1;
			}
			जइ (whole > LLONG_MAX / 10) {
				errno = ERANGE;
				प्रत्यागम -1;
			}
			whole *= 10;
			जइ (i > LLONG_MAX - whole) {
				errno = ERANGE;
				प्रत्यागम -1;
			}
			whole += i;
		}
	}

	जइ (sign)
		whole *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	जइ (!*p) {
		*result = whole;
		प्रत्यागम 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	प्रति (i = 0; i < SCALE_LENGTH; i++) {

		/* Are we there yet? */
		जइ (*p == scale_chars[i] ||
			*p == tolower((unsigned वर्ण)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			जइ (isalnum((unsigned वर्ण)*(p+1))) {
				errno = EINVAL;
				प्रत्यागम -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			जइ (whole > LLONG_MAX / scale_fact ||
			    whole < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				प्रत्यागम -1;
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
			जाव (muls > 0 && divs > 0) {
				जइ (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} अण्णहा {
					fpart /= 10;
					divs--;
				}
			}
			जाव (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			जाव (divs > 0) {
				fpart /= 10;
				divs--;
			}
			जइ (sign == -1)
				whole -= fpart;
			अण्णहा
				whole += fpart;
			*result = whole;
			प्रत्यागम 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	प्रत्यागम -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
पूर्णाङ्क
fmt_scaled(long long सङ्ख्या, वर्ण *result)
{
	long long abval, fract = 0;
	unsigned पूर्णाङ्क i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	जइ (सङ्ख्या == LLONG_MIN) {
		errno = ERANGE;
		प्रत्यागम -1;
	}

	abval = llabs(सङ्ख्या);

	/* Also check for numbers that are just too darned big to format. */
	जइ (abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		errno = ERANGE;
		प्रत्यागम -1;
	}

	/* scale whole part; get unscaled fraction */
	प्रति (i = 0; i < SCALE_LENGTH; i++) {
		जइ (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			सङ्ख्या /= scale_factors[i];
			जइ (i > 0)
				fract /= scale_factors[i - 1];
			भङ्ग;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	जइ (fract >= 10) {
		जइ (सङ्ख्या >= 0)
			सङ्ख्या++;
		अण्णहा
			सङ्ख्या--;
		fract = 0;
	} अण्णहा जइ (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	जइ (सङ्ख्या == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	अण्णहा जइ (unit == NONE || सङ्ख्या >= 100 || सङ्ख्या <= -100) {
		जइ (fract >= 5) {
			जइ (सङ्ख्या >= 0)
				सङ्ख्या++;
			अण्णहा
				सङ्ख्या--;
		}
		(शून्य)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			सङ्ख्या, scale_chars[unit]);
	} अण्णहा
		(शून्य)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			सङ्ख्या, fract, scale_chars[unit]);

	प्रत्यागम 0;
}

#ifdef	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	वर्ण *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	long long ninput = 10483892, result;

	जइ (scan_scaled(cinput, &result) == 0)
		printf("\"%s\" -> %lld\n", cinput, result);
	अण्णहा
		perror(cinput);

	जइ (fmt_scaled(ninput, buf) == 0)
		printf("%lld -> \"%s\"\n", ninput, buf);
	अण्णहा
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	प्रत्यागम 0;
}
#endif

#endif /* HAVE_FMT_SCALED */
