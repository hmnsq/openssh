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

#അന്തര്ഭാവ "includes.h"

#ifndef HAVE_FMT_SCALED

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <limits.h>

തരനിർവചനം എണ്ണൽ {
	NONE = 0, KILO = 1, MEGA = 2, GIGA = 3, TERA = 4, PETA = 5, EXA = 6
} unit_type;

/* These three arrays MUST be in sync!  XXX make a struct */
സ്ഥിതം സ്ഥിരം unit_type units[] = { NONE, KILO, MEGA, GIGA, TERA, PETA, EXA };
സ്ഥിതം സ്ഥിരം അക്ഷരം scale_chars[] = "BKMGTPE";
സ്ഥിതം സ്ഥിരം long long scale_factors[] = {
	1LL,
	1024LL,
	1024LL*1024,
	1024LL*1024*1024,
	1024LL*1024*1024*1024,
	1024LL*1024*1024*1024*1024,
	1024LL*1024*1024*1024*1024*1024,
};
#define	SCALE_LENGTH (വലുപ്പം(units)/വലുപ്പം(units[0]))

#define MAX_DIGITS (SCALE_LENGTH * 3)	/* XXX strlen(sprintf("%lld", -1)? */

/* Convert the given input string "scaled" into numeric in "result".
 * Return 0 on success, -1 and errno set on error.
 */
പൂർണ്ണസംഖ്യ
scan_scaled(അക്ഷരം *scaled, long long *result)
{
	അക്ഷരം *p = scaled;
	പൂർണ്ണസംഖ്യ sign = 0;
	unsigned പൂർണ്ണസംഖ്യ i, ndigits = 0, fract_digits = 0, muls = 0, divs = 0;
	long long scale_fact = 1, whole = 0, fpart = 0;

	/* Skip leading whitespace */
	ആകുമ്പോൾ (isascii((unsigned അക്ഷരം)*p) && isspace((unsigned അക്ഷരം)*p))
		++p;

	/* Then at most one leading + or - */
	ആകുമ്പോൾ (*p == '-' || *p == '+') {
		എങ്കിൽ (*p == '-') {
			എങ്കിൽ (sign) {
				errno = EINVAL;
				തിരികെ -1;
			}
			sign = -1;
			++p;
		} അല്ലെങ്കിൽ എങ്കിൽ (*p == '+') {
			എങ്കിൽ (sign) {
				errno = EINVAL;
				തിരികെ -1;
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
	വേണ്ടി (; isascii((unsigned അക്ഷരം)*p) &&
	    (isdigit((unsigned അക്ഷരം)*p) || *p=='.'); ++p) {
		എങ്കിൽ (*p == '.') {
			എങ്കിൽ (fract_digits > 0) {	/* oops, more than one '.' */
				errno = EINVAL;
				തിരികെ -1;
			}
			fract_digits = 1;
			തുടരുക;
		}

		i = (*p) - '0';			/* whew! finally a digit we can use */
		എങ്കിൽ (fract_digits > 0) {
			എങ്കിൽ (fract_digits >= MAX_DIGITS-1)
				/* ignore extra fractional digits */
				തുടരുക;
			fract_digits++;		/* for later scaling */
			എങ്കിൽ (fpart > LLONG_MAX / 10) {
				errno = ERANGE;
				തിരികെ -1;
			}
			fpart *= 10;
			എങ്കിൽ (i > LLONG_MAX - fpart) {
				errno = ERANGE;
				തിരികെ -1;
			}
			fpart += i;
		} അല്ലെങ്കിൽ {				/* normal digit */
			എങ്കിൽ (++ndigits >= MAX_DIGITS) {
				errno = ERANGE;
				തിരികെ -1;
			}
			എങ്കിൽ (whole > LLONG_MAX / 10) {
				errno = ERANGE;
				തിരികെ -1;
			}
			whole *= 10;
			എങ്കിൽ (i > LLONG_MAX - whole) {
				errno = ERANGE;
				തിരികെ -1;
			}
			whole += i;
		}
	}

	എങ്കിൽ (sign)
		whole *= sign;

	/* If no scale factor given, we're done. fraction is discarded. */
	എങ്കിൽ (!*p) {
		*result = whole;
		തിരികെ 0;
	}

	/* Validate scale factor, and scale whole and fraction by it. */
	വേണ്ടി (i = 0; i < SCALE_LENGTH; i++) {

		/* Are we there yet? */
		എങ്കിൽ (*p == scale_chars[i] ||
			*p == tolower((unsigned അക്ഷരം)scale_chars[i])) {

			/* If it ends with alphanumerics after the scale char, bad. */
			എങ്കിൽ (isalnum((unsigned അക്ഷരം)*(p+1))) {
				errno = EINVAL;
				തിരികെ -1;
			}
			scale_fact = scale_factors[i];

			/* check for overflow and underflow after scaling */
			എങ്കിൽ (whole > LLONG_MAX / scale_fact ||
			    whole < LLONG_MIN / scale_fact) {
				errno = ERANGE;
				തിരികെ -1;
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
			ആകുമ്പോൾ (muls > 0 && divs > 0) {
				എങ്കിൽ (fpart <= LLONG_MAX / 1024) {
					fpart *= 1024;
					muls--;
				} അല്ലെങ്കിൽ {
					fpart /= 10;
					divs--;
				}
			}
			ആകുമ്പോൾ (muls > 0) {
				fpart *= 1024;
				muls--;
			}
			ആകുമ്പോൾ (divs > 0) {
				fpart /= 10;
				divs--;
			}
			എങ്കിൽ (sign == -1)
				whole -= fpart;
			അല്ലെങ്കിൽ
				whole += fpart;
			*result = whole;
			തിരികെ 0;
		}
	}

	/* Invalid unit or character */
	errno = EINVAL;
	തിരികെ -1;
}

/* Format the given "number" into human-readable form in "result".
 * Result must point to an allocated buffer of length FMT_SCALED_STRSIZE.
 * Return 0 on success, -1 and errno set if error.
 */
പൂർണ്ണസംഖ്യ
fmt_scaled(long long സംഖ്യ, അക്ഷരം *result)
{
	long long abval, fract = 0;
	unsigned പൂർണ്ണസംഖ്യ i;
	unit_type unit = NONE;

	/* Not every negative long long has a positive representation. */
	എങ്കിൽ (സംഖ്യ == LLONG_MIN) {
		errno = ERANGE;
		തിരികെ -1;
	}

	abval = llabs(സംഖ്യ);

	/* Also check for numbers that are just too darned big to format. */
	എങ്കിൽ (abval / 1024 >= scale_factors[SCALE_LENGTH-1]) {
		errno = ERANGE;
		തിരികെ -1;
	}

	/* scale whole part; get unscaled fraction */
	വേണ്ടി (i = 0; i < SCALE_LENGTH; i++) {
		എങ്കിൽ (abval/1024 < scale_factors[i]) {
			unit = units[i];
			fract = (i == 0) ? 0 : abval % scale_factors[i];
			സംഖ്യ /= scale_factors[i];
			എങ്കിൽ (i > 0)
				fract /= scale_factors[i - 1];
			നിർത്തുക;
		}
	}

	fract = (10 * fract + 512) / 1024;
	/* if the result would be >= 10, round main number */
	എങ്കിൽ (fract >= 10) {
		എങ്കിൽ (സംഖ്യ >= 0)
			സംഖ്യ++;
		അല്ലെങ്കിൽ
			സംഖ്യ--;
		fract = 0;
	} അല്ലെങ്കിൽ എങ്കിൽ (fract < 0) {
		/* shouldn't happen */
		fract = 0;
	}

	എങ്കിൽ (സംഖ്യ == 0)
		strlcpy(result, "0B", FMT_SCALED_STRSIZE);
	അല്ലെങ്കിൽ എങ്കിൽ (unit == NONE || സംഖ്യ >= 100 || സംഖ്യ <= -100) {
		എങ്കിൽ (fract >= 5) {
			എങ്കിൽ (സംഖ്യ >= 0)
				സംഖ്യ++;
			അല്ലെങ്കിൽ
				സംഖ്യ--;
		}
		(ശൂന്യം)snprintf(result, FMT_SCALED_STRSIZE, "%lld%c",
			സംഖ്യ, scale_chars[unit]);
	} അല്ലെങ്കിൽ
		(ശൂന്യം)snprintf(result, FMT_SCALED_STRSIZE, "%lld.%1lld%c",
			സംഖ്യ, fract, scale_chars[unit]);

	തിരികെ 0;
}

#ifdef	MAIN
/*
 * This is the original version of the program in the man page.
 * Copy-and-paste whatever you need from it.
 */
പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	അക്ഷരം *cinput = "1.5K", buf[FMT_SCALED_STRSIZE];
	long long ninput = 10483892, result;

	എങ്കിൽ (scan_scaled(cinput, &result) == 0)
		printf("\"%s\" -> %lld\n", cinput, result);
	അല്ലെങ്കിൽ
		perror(cinput);

	എങ്കിൽ (fmt_scaled(ninput, buf) == 0)
		printf("%lld -> \"%s\"\n", ninput, buf);
	അല്ലെങ്കിൽ
		fprintf(stderr, "%lld invalid (%s)\n", ninput, strerror(errno));

	തിരികെ 0;
}
#endif

#endif /* HAVE_FMT_SCALED */
