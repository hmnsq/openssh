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

#અન્તર્ભાવ "includes.h"

#ifndef HAVE_FMT_SCALED

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <limits.h>

પ્રકારવ્યાખ્યા ગણના {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
સ્થિર અચલ unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
સ્થિર અચલ અક્ષર scale_chars[] = "BKMGTPE";
સ્થિર અચલ long long scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#define	SCALE_LENGTH (કદ(units)/કદ(units[0]))

#define MAX_DIGITS (SCALE_LENGTH * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
પૂર્ણાંક
scan_scaled(અક્ષર *scaled, long long *result)
{
	અક્ષર *p = scaled;
	પૂર્ણાંક sign = 0;
	unsigned પૂર્ણાંક i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	long long scale_fact = 1, whole = 0, fpart = 0;

	/* Skip leading whitespace */
	જ્યારે (isascii((unsigned અક્ષર)*p) && isspace((unsigned અક્ષર)*p))
		++p;

	/* Then at most one leading + or - */
	જ્યારે (*p == '-' || *p == '+') {
		જો (*p == '-') {
			જો (sign) {
				errno = EINVAL;
				પાછા -1;
			}
			sign = -1;
			++p;
		} નહીંતર જો (*p == '+') {
			જો (sign) {
				errno = EINVAL;
				પાછા -1;
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
	માટે (; isascii((unsigned અક્ષર)*p) &&
	    (isdigit((unsigned અક્ષર)*p) || *p=='.'); ++p) {
		જો (*p == '.') {
			જો (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				પાછા -1;
			}
			fract_digits = 1;
			ચાલુ;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		જો (fract_digits > 0) {
			જો (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				ચાલુ;
			fract_digits++;		/* for later scaling */
			જો (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				પાછા -1;
			}
			fpart *= 10;
			જો (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				પાછા -1;
			}
			fpart += i;
		} નહીંતર {				/* normal digit */
			જો (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				પાછા -1;
			}
			જો (whole > LLONG_MAX / 10) {
				errno = ERANGE;
				પાછા -1;
			}
			whole *= 10;
			જો (i > LLONG_MAX - whole) {
				errno = ERANGE;
				પાછા -1;
			}
			whole += i;
		}
	}

	જો (sign)
		whole *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	જો (!*p) {
		*result = whole;
		પાછા 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	માટે (i = 0; i < SCALE_LENGTH; i++) {

		/* Are we there yet? */
		જો (*p == scale_chars[i] ||
			*p == tolower((unsigned અક્ષર)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			જો (isalnum((unsigned અક્ષર)*(p+1))) {
				errno = EINVAL;
				પાછા -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			જો (whole > LLONG_MAX / scale_fact ||
			    whole < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				પાછા -1;
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
			જ્યારે (muls > 0 && divs > 0) {
				જો (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} નહીંતર {
					fpart /= 10;
					divs--;
				}
			}
			જ્યારે (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			જ્યારે (divs > 0) {
				fpart /= 10;
				divs--;
			}
			જો (sign == -1)
				whole -= fpart;
			નહીંતર
				whole += fpart;
			*result = whole;
			પાછા 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	પાછા -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
પૂર્ણાંક
fmt_scaled(long long સંખ્યા, અક્ષર *result)
{
	long long abval, fract = 0;
	unsigned પૂર્ણાંક i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	જો (સંખ્યા == LLONG_MIN) {
		errno = ERANGE;
		પાછા -1;
	}

	abval = llabs(સંખ્યા);

	/* Also check for numbers that are just too darned big to format. */
	જો (abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		errno = ERANGE;
		પાછા -1;
	}

	/* scale whole part; get unscaled fraction */
	માટે (i = 0; i < SCALE_LENGTH; i++) {
		જો (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			સંખ્યા /= scale_factors[i];
			જો (i > 0)
				fract /= scale_factors[i - 1];
			તોડો;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	જો (fract >= 10) {
		જો (સંખ્યા >= 0)
			સંખ્યા++;
		નહીંતર
			સંખ્યા--;
		fract = 0;
	} નહીંતર જો (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	જો (સંખ્યા == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	નહીંતર જો (unit == NONE || સંખ્યા >= 100 || સંખ્યા <= -100) {
		જો (fract >= 5) {
			જો (સંખ્યા >= 0)
				સંખ્યા++;
			નહીંતર
				સંખ્યા--;
		}
		(શૂન્ય)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			સંખ્યા, scale_chars[unit]);
	} નહીંતર
		(શૂન્ય)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			સંખ્યા, fract, scale_chars[unit]);

	પાછા 0;
}

#ifdef	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	અક્ષર *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	long long ninput = 10483892, result;

	જો (scan_scaled(cinput, &result) == 0)
		printf("\"%s\" -> %lld\n", cinput, result);
	નહીંતર
		perror(cinput);

	જો (fmt_scaled(ninput, buf) == 0)
		printf("%lld -> \"%s\"\n", ninput, buf);
	નહીંતર
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	પાછા 0;
}
#endif

#endif /* HAVE_FMT_SCALED */
