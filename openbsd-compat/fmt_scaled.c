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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_FMT_SCALED

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <ctype.h>
#అన్తర్భావ <limits.h>

రకనిర్వచనం గణన {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
స్థిర స్థిరరాశి unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
స్థిర స్థిరరాశి అక్షరం scale_chars[] = "BKMGTPE";
స్థిర స్థిరరాశి దీర్ఘ దీర్ఘ scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#నిర్వచించు	SCALE_నిడివి (పరిమాణం(units)/పరిమాణం(units[0]))

#నిర్వచించు MAX_DIGITS (SCALE_నిడివి * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
పూర్ణాంకం
పరిశీలన_scaled(అక్షరం *scaled, దీర్ఘ దీర్ఘ *ఫలితం)
{
	అక్షరం *p = scaled;
	పూర్ణాంకం sign = 0;
	గుర్తులేని పూర్ణాంకం i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	దీర్ఘ దీర్ఘ scale_fact = 1, సంపూర్ణ = 0, fpart = 0;

	/* Skip leading whitespace */
	అయితే (isascii((గుర్తులేని అక్షరం)*p) && ఖాళీనా((గుర్తులేని అక్షరం)*p))
		++p;

	/* Then at most one leading + or - */
	అయితే (*p == '-' || *p == '+') {
		ఒకవేళ (*p == '-') {
			ఒకవేళ (sign) {
				errno = EINVAL;
				తిరిగి -1;
			}
			sign = -1;
			++p;
		} లేకపోతే ఒకవేళ (*p == '+') {
			ఒకవేళ (sign) {
				errno = EINVAL;
				తిరిగి -1;
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
	కొరకు (; isascii((గుర్తులేని అక్షరం)*p) &&
	    (అంకెనా((గుర్తులేని అక్షరం)*p) || *p=='.'); ++p) {
		ఒకవేళ (*p == '.') {
			ఒకవేళ (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				తిరిగి -1;
			}
			fract_digits = 1;
			కొనసాగు;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		ఒకవేళ (fract_digits > 0) {
			ఒకవేళ (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				కొనసాగు;
			fract_digits++;		/* for later scaling */
			ఒకవేళ (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				తిరిగి -1;
			}
			fpart *= 10;
			ఒకవేళ (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				తిరిగి -1;
			}
			fpart += i;
		} లేకపోతే {				/* normal digit */
			ఒకవేళ (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				తిరిగి -1;
			}
			ఒకవేళ (సంపూర్ణ > LLONG_MAX / 10) {
				errno = ERANGE;
				తిరిగి -1;
			}
			సంపూర్ణ *= 10;
			ఒకవేళ (i > LLONG_MAX - సంపూర్ణ) {
				errno = ERANGE;
				తిరిగి -1;
			}
			సంపూర్ణ += i;
		}
	}

	ఒకవేళ (sign)
		సంపూర్ణ *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	ఒకవేళ (!*p) {
		*ఫలితం = సంపూర్ణ;
		తిరిగి 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	కొరకు (i = 0; i < SCALE_నిడివి; i++) {

		/* Are we there yet? */
		ఒకవేళ (*p == scale_chars[i] ||
			*p == tolower((గుర్తులేని అక్షరం)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			ఒకవేళ (అక్షరమా_అంకెనా((గుర్తులేని అక్షరం)*(p+1))) {
				errno = EINVAL;
				తిరిగి -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			ఒకవేళ (సంపూర్ణ > LLONG_MAX / scale_fact ||
			    సంపూర్ణ < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				తిరిగి -1;
			}

			/* scale whole part */
			సంపూర్ణ *= scale_fact;

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
			అయితే (muls > 0 && divs > 0) {
				ఒకవేళ (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} లేకపోతే {
					fpart /= 10;
					divs--;
				}
			}
			అయితే (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			అయితే (divs > 0) {
				fpart /= 10;
				divs--;
			}
			ఒకవేళ (sign == -1)
				సంపూర్ణ -= fpart;
			లేకపోతే
				సంపూర్ణ += fpart;
			*ఫలితం = సంపూర్ణ;
			తిరిగి 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	తిరిగి -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
పూర్ణాంకం
fmt_scaled(దీర్ఘ దీర్ఘ సంఖ్య, అక్షరం *ఫలితం)
{
	దీర్ఘ దీర్ఘ abval, fract = 0;
	గుర్తులేని పూర్ణాంకం i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	ఒకవేళ (సంఖ్య == LLONG_MIN) {
		errno = ERANGE;
		తిరిగి -1;
	}

	abval = llabs(సంఖ్య);

	/* Also check for numbers that are just too darned big to format. */
	ఒకవేళ (abval / 1024 >= scale_factors[SCALE_నిడివి-1]) {
		errno = ERANGE;
		తిరిగి -1;
	}

	/* scale whole part; get unscaled fraction */
	కొరకు (i = 0; i < SCALE_నిడివి; i++) {
		ఒకవేళ (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			సంఖ్య /= scale_factors[i];
			ఒకవేళ (i > 0)
				fract /= scale_factors[i - 1];
			ఆపు;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	ఒకవేళ (fract >= 10) {
		ఒకవేళ (సంఖ్య >= 0)
			సంఖ్య++;
		లేకపోతే
			సంఖ్య--;
		fract = 0;
	} లేకపోతే ఒకవేళ (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	ఒకవేళ (సంఖ్య == 0)
		strlcpy(ఫలితం, "0B", FMT_SCALED_STRSIZE);
	లేకపోతే ఒకవేళ (unit == NONE || సంఖ్య >= 100 || సంఖ్య <= -100) {
		ఒకవేళ (fract >= 5) {
			ఒకవేళ (సంఖ్య >= 0)
				సంఖ్య++;
			లేకపోతే
				సంఖ్య--;
		}
		(శూన్య)snprintf(ఫలితం, FMT_SCALED_STRSIZE, "%lld%c",
			సంఖ్య, scale_chars[unit]);
	} లేకపోతే
		(శూన్య)snprintf(ఫలితం, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			సంఖ్య, fract, scale_chars[unit]);

	తిరిగి 0;
}

#నిర్వచితమైతే	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	అక్షరం *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	దీర్ఘ దీర్ఘ ninput = 10483892, ఫలితం;

	ఒకవేళ (పరిశీలన_scaled(cinput, &ఫలితం) == 0)
		రాయి("\"%s\" -> %lld\n", cinput, ఫలితం);
	లేకపోతే
		perror(cinput);

	ఒకవేళ (fmt_scaled(ninput, buf) == 0)
		రాయి("%lld -> \"%s\"\n", ninput, buf);
	లేకపోతే
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	తిరిగి 0;
}
#అయితే_ముగింపు

#అయితే_ముగింపు /* HAVE_FMT_SCALED */
