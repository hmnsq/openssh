/*
 * Copyright Patrick Powell 1995
 * This code is based on code written by Patrick Powell (papowell@astart.com)
 * It may be used for any purpose as long as this notice remains intact
 * on all source code distributions
 */

/**************************************************************
 * Original:
 * Patrick Powell Tue Apr 11 09:48:21 PDT 1995
 * A bombproof version of doprnt (dopr) included.
 * Sigh.  This sort of thing is always nasty do deal with.  Note that
 * the version here does not include floating point...
 *
 * snprintf() is used instead of sprintf() as it does limit checks
 * for string length.  This covers a nasty loophole.
 *
 * The other functions are there to prevent NULL pointers from
 * causing nast effects.
 *
 * More Recently:
 *  Brandon Long <blong@fiction.net> 9/15/96 for mutt 0.43
 *  This was ugly.  It is still ugly.  I opted out of floating point
 *  numbers, but the formatter understands just about everything
 *  from the normal C string format, at least as far as I can tell from
 *  the Solaris 2.5 printf(3S) man page.
 *
 *  Brandon Long <blong@fiction.net> 10/22/97 for mutt 0.87.1
 *    Ok, added some minimal floating point support, which means this
 *    probably requires libm on most operating systems.  Don't yet
 *    support the exponent (e,E) and sigfig (g,G).  Also, fmtint()
 *    was pretty badly broken, it just wasn't being exercised in ways
 *    which showed it, so that's been fixed.  Also, formatted the code
 *    to mutt conventions, and removed dead code left over from the
 *    original.  Also, there is now a builtin-test, just compile with:
 *           gcc -DTEST_SNPRINTF -o snprintf snprintf.c -lm
 *    and run snprintf for results.
 *
 *  Thomas Roessler <roessler@guug.de> 01/27/98 for mutt 0.89i
 *    The PGP code was using unsigned hexadecimal formats.
 *    Unfortunately, unsigned formats simply didn't work.
 *
 *  Michael Elkins <me@cs.hmc.edu> 03/05/98 for mutt 0.90.8
 *    The original code assumed that both snprintf() and vsnprintf() were
 *    missing.  Some systems only have snprintf() but not vsnprintf(), so
 *    the code is now broken down under HAVE_SNPRINTF and HAVE_VSNPRINTF.
 *
 *  Andrew Tridgell (tridge@samba.org) Oct 1998
 *    fixed handling of %.0f
 *    added test for HAVE_LONG_DOUBLE
 *
 * tridge@samba.org, idra@samba.org, April 2001
 *    got rid of fcvt code (twas buggy and made testing harder)
 *    added C99 semantics
 *
 * date: 2002/12/19 19:56:31;  author: herb;  state: Exp;  lines: +2 -0
 * actually print args for %g and %e
 *
 * date: 2002/06/03 13:37:52;  author: jmcd;  state: Exp;  lines: +8 -0
 * Since includes.h isn't included here, VA_COPY has to be defined here.  I don't
 * see any include file that is guaranteed to be here, so I'm defining it
 * locally.  Fixes AIX and Solaris builds.
 *
 * date: 2002/06/03 03:07:24;  author: tridge;  state: Exp;  lines: +5 -13
 * put the ifdef for HAVE_VA_COPY in one place rather than in lots of
 * functions
 *
 * date: 2002/05/17 14:51:22;  author: jmcd;  state: Exp;  lines: +21 -4
 * Fix usage of va_list passed as an arg.  Use __va_copy before using it
 * when it exists.
 *
 * date: 2002/04/16 22:38:04;  author: idra;  state: Exp;  lines: +20 -14
 * Fix incorrect zpadlen handling in fmtfp.
 * Thanks to Ollie Oldham <ollie.oldham@metro-optix.com> for spotting it.
 * few mods to make it easier to compile the tests.
 * added the "Ollie" test to the floating point ones.
 *
 * Martin Pool (mbp@samba.org) April 2003
 *    Remove NO_CONFIG_H so that the test case can be built within a source
 *    tree with less trouble.
 *    Remove unnecessary SAFE_FREE() definition.
 *
 * Martin Pool (mbp@samba.org) May 2003
 *    Put in a prototype for dummy_snprintf() to quiet compiler warnings.
 *
 *    Move #endif to make sure VA_COPY, LDOUBLE, etc are defined even
 *    if the C library has some snprintf functions already.
 *
 * Damien Miller (djm@mindrot.org) Jan 2007
 *    Fix integer overflows in return value.
 *    Make formatting quite a bit faster by inlining dopr_outch()
 *
 **************************************************************/

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಆದರೆ defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <errno.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LONG_DOUBLE
# define LDOUBLE ದೀರ್ಘ ದ್ವಿಗುಣ
#ಇಲ್ಲದಿದ್ದರೆ
# define LDOUBLE ದ್ವಿಗುಣ
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LONG_LONG
# define LLONG ದೀರ್ಘ ದೀರ್ಘ
#ಇಲ್ಲದಿದ್ದರೆ
# define LLONG ದೀರ್ಘ
#ಆದರೆ_ಅಂತ್ಯ

/*
 * dopr(): poor man's version of doprintf
 */

/* format read states */
#ವ್ಯಾಖ್ಯಾನಿಸು DP_S_DEFAULT 0
#ವ್ಯಾಖ್ಯಾನಿಸು DP_S_FLAGS   1
#ವ್ಯಾಖ್ಯಾನಿಸು DP_S_MIN     2
#ವ್ಯಾಖ್ಯಾನಿಸು DP_S_DOT     3
#ವ್ಯಾಖ್ಯಾನಿಸು DP_S_MAX     4
#ವ್ಯಾಖ್ಯಾನಿಸು DP_S_MOD     5
#ವ್ಯಾಖ್ಯಾನಿಸು DP_S_CONV    6
#ವ್ಯಾಖ್ಯಾನಿಸು DP_S_ಮುಗಿದ    7

/* format flags - Bits */
#ವ್ಯಾಖ್ಯಾನಿಸು DP_F_MINUS	(1 << 0)
#ವ್ಯಾಖ್ಯಾನಿಸು DP_F_PLUS	(1 << 1)
#ವ್ಯಾಖ್ಯಾನಿಸು DP_F_SPACE	(1 << 2)
#ವ್ಯಾಖ್ಯಾನಿಸು DP_F_ಅಂಕೆ	(1 << 3)
#ವ್ಯಾಖ್ಯಾನಿಸು DP_F_ZERO	(1 << 4)
#ವ್ಯಾಖ್ಯಾನಿಸು DP_F_ಮೇಲೆ		(1 << 5)
#ವ್ಯಾಖ್ಯಾನಿಸು DP_F_UNSIGNED	(1 << 6)

/* Conversion Flags */
#ವ್ಯಾಖ್ಯಾನಿಸು DP_C_SHORT   1
#ವ್ಯಾಖ್ಯಾನಿಸು DP_C_LONG    2
#ವ್ಯಾಖ್ಯಾನಿಸು DP_C_LDOUBLE 3
#ವ್ಯಾಖ್ಯಾನಿಸು DP_C_LLONG   4
#ವ್ಯಾಖ್ಯಾನಿಸು DP_C_ಗಾತ್ರ    5
#ವ್ಯಾಖ್ಯಾನಿಸು DP_C_INTMAX  6

#ವ್ಯಾಖ್ಯಾನಿಸು char_ಗಮ್ಯ_int(p) ((p)- '0')
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ MAX
# define MAX(p,q) (((p) >= (q)) ? (p) : (q))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು DOPR_OUTCH(buf, pos, buflen, thechar) \
	ಮಾಡು { \
		ಆದರೆ (pos + 1 >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) { \
			errno = ERANGE; \
			ಹಿಂತಿರುಗಿ -1; \
		} \
		ಆದರೆ (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} ಆಗ (0)

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ dopr(ಅಕ್ಷರ *ಬಫರ್, ಗಾತ್ರ_t maxlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *format,
    va_list ವಾದಗಳು_ಒಳ);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ fmtstr(ಅಕ್ಷರ *ಬಫರ್, ಗಾತ್ರ_t *currlen, ಗಾತ್ರ_t maxlen,
    ಅಕ್ಷರ *ಮೌಲ್ಯ, ಪೂರ್ಣಾಂಕ flags, ಪೂರ್ಣಾಂಕ min, ಪೂರ್ಣಾಂಕ max);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ fmtint(ಅಕ್ಷರ *ಬಫರ್, ಗಾತ್ರ_t *currlen, ಗಾತ್ರ_t maxlen,
    intmax_t ಮೌಲ್ಯ, ಪೂರ್ಣಾಂಕ ತಳ, ಪೂರ್ಣಾಂಕ min, ಪೂರ್ಣಾಂಕ max, ಪೂರ್ಣಾಂಕ flags);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ fmtfp(ಅಕ್ಷರ *ಬಫರ್, ಗಾತ್ರ_t *currlen, ಗಾತ್ರ_t maxlen,
    LDOUBLE fvalue, ಪೂರ್ಣಾಂಕ min, ಪೂರ್ಣಾಂಕ max, ಪೂರ್ಣಾಂಕ flags);

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
dopr(ಅಕ್ಷರ *ಬಫರ್, ಗಾತ್ರ_t maxlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *format, va_list ವಾದಗಳು_ಒಳ)
{
	ಅಕ್ಷರ ch;
	intmax_t ಮೌಲ್ಯ;
	LDOUBLE fvalue;
	ಅಕ್ಷರ *strvalue;
	ಪೂರ್ಣಾಂಕ min;
	ಪೂರ್ಣಾಂಕ max;
	ಪೂರ್ಣಾಂಕ state;
	ಪೂರ್ಣಾಂಕ flags;
	ಪೂರ್ಣಾಂಕ cflags;
	ಗಾತ್ರ_t currlen;
	va_list ವಾದಗಳು;

	VA_COPY(ವಾದಗಳು, ವಾದಗಳು_ಒಳ);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	ಆಗ (state != DP_S_ಮುಗಿದ) {
		ಆದರೆ (ch == '\0')
			state = DP_S_ಮುಗಿದ;

		ಆಯ್ಕೆ(state) {
		ಸ್ಥಿತಿ DP_S_DEFAULT:
			ಆದರೆ (ch == '%')
				state = DP_S_FLAGS;
			ಇಲ್ಲದಿದ್ದರೆ
				DOPR_OUTCH(ಬಫರ್, currlen, maxlen, ch);
			ch = *format++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ DP_S_FLAGS:
			ಆಯ್ಕೆ (ch) {
			ಸ್ಥಿತಿ '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ '#':
				flags |= DP_F_ಅಂಕೆ;
				ch = *format++;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				ನಿಲ್ಲಿಸು;
			ಪೂರ್ವನಿಯೋಜಿತ:
				state = DP_S_MIN;
				ನಿಲ್ಲಿಸು;
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ DP_S_MIN:
			ಆದರೆ (ಅಂಕಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)ch)) {
				min = 10*min + char_ಗಮ್ಯ_int (ch);
				ch = *format++;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ch == '*') {
				min = va_arg (ವಾದಗಳು, ಪೂರ್ಣಾಂಕ);
				ch = *format++;
				state = DP_S_DOT;
			} ಇಲ್ಲದಿದ್ದರೆ {
				state = DP_S_DOT;
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ DP_S_DOT:
			ಆದರೆ (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} ಇಲ್ಲದಿದ್ದರೆ {
				state = DP_S_MOD;
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ DP_S_MAX:
			ಆದರೆ (ಅಂಕಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)ch)) {
				ಆದರೆ (max < 0)
					max = 0;
				max = 10*max + char_ಗಮ್ಯ_int (ch);
				ch = *format++;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ch == '*') {
				max = va_arg (ವಾದಗಳು, ಪೂರ್ಣಾಂಕ);
				ch = *format++;
				state = DP_S_MOD;
			} ಇಲ್ಲದಿದ್ದರೆ {
				state = DP_S_MOD;
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ DP_S_MOD:
			ಆಯ್ಕೆ (ch) {
			ಸ್ಥಿತಿ 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				ಆದರೆ (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'z':
				cflags = DP_C_ಗಾತ್ರ;
				ch = *format++;
				ನಿಲ್ಲಿಸು;
			ಪೂರ್ವನಿಯೋಜಿತ:
				ನಿಲ್ಲಿಸು;
			}
			state = DP_S_CONV;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ DP_S_CONV:
			ಆಯ್ಕೆ (ch) {
			ಸ್ಥಿತಿ 'd':
			ಸ್ಥಿತಿ 'i':
				ಆದರೆ (cflags == DP_C_SHORT)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, ಪೂರ್ಣಾಂಕ);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_LONG)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, ದೀರ್ಘ ಪೂರ್ಣಾಂಕ);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_LLONG)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, LLONG);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_ಗಾತ್ರ)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, ssize_t);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_INTMAX)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, intmax_t);
				ಇಲ್ಲದಿದ್ದರೆ
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, ಪೂರ್ಣಾಂಕ);
				ಆದರೆ (fmtint(ಬಫರ್, &currlen, maxlen,
				    ಮೌಲ್ಯ, 10, min, max, flags) == -1)
					ಹೋಗು fail;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'o':
				flags |= DP_F_UNSIGNED;
				ಆದರೆ (cflags == DP_C_SHORT)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_LONG)
					ಮೌಲ್ಯ = (ದೀರ್ಘ)va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಪೂರ್ಣಾಂಕ);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_LLONG)
					ಮೌಲ್ಯ = (ದೀರ್ಘ)va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ LLONG);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_ಗಾತ್ರ)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, ಗಾತ್ರ_t);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ notyet
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_INTMAX)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, uintmax_t);
#ಆದರೆ_ಅಂತ್ಯ
				ಇಲ್ಲದಿದ್ದರೆ
					ಮೌಲ್ಯ = (ದೀರ್ಘ)va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ);
				ಆದರೆ (fmtint(ಬಫರ್, &currlen, maxlen, ಮೌಲ್ಯ,
				    8, min, max, flags) == -1)
					ಹೋಗು fail;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'u':
				flags |= DP_F_UNSIGNED;
				ಆದರೆ (cflags == DP_C_SHORT)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_LONG)
					ಮೌಲ್ಯ = (ದೀರ್ಘ)va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಪೂರ್ಣಾಂಕ);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_LLONG)
					ಮೌಲ್ಯ = (LLONG)va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ LLONG);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_ಗಾತ್ರ)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, ಗಾತ್ರ_t);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ notyet
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_INTMAX)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, uintmax_t);
#ಆದರೆ_ಅಂತ್ಯ
				ಇಲ್ಲದಿದ್ದರೆ
					ಮೌಲ್ಯ = (ದೀರ್ಘ)va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ);
				ಆದರೆ (fmtint(ಬಫರ್, &currlen, maxlen, ಮೌಲ್ಯ,
				    10, min, max, flags) == -1)
					ಹೋಗು fail;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'X':
				flags |= DP_F_ಮೇಲೆ;
			ಸ್ಥಿತಿ 'x':
				flags |= DP_F_UNSIGNED;
				ಆದರೆ (cflags == DP_C_SHORT)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_LONG)
					ಮೌಲ್ಯ = (ದೀರ್ಘ)va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ಪೂರ್ಣಾಂಕ);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_LLONG)
					ಮೌಲ್ಯ = (LLONG)va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ LLONG);
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_ಗಾತ್ರ)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, ಗಾತ್ರ_t);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ notyet
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_INTMAX)
					ಮೌಲ್ಯ = va_arg (ವಾದಗಳು, uintmax_t);
#ಆದರೆ_ಅಂತ್ಯ
				ಇಲ್ಲದಿದ್ದರೆ
					ಮೌಲ್ಯ = (ದೀರ್ಘ)va_arg (ವಾದಗಳು, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ);
				ಆದರೆ (fmtint(ಬಫರ್, &currlen, maxlen, ಮೌಲ್ಯ,
				    16, min, max, flags) == -1)
					ಹೋಗು fail;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'f':
				ಆದರೆ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (ವಾದಗಳು, LDOUBLE);
				ಇಲ್ಲದಿದ್ದರೆ
					fvalue = va_arg (ವಾದಗಳು, ದ್ವಿಗುಣ);
				ಆದರೆ (fmtfp(ಬಫರ್, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ಹೋಗು fail;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'E':
				flags |= DP_F_ಮೇಲೆ;
			ಸ್ಥಿತಿ 'e':
				ಆದರೆ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (ವಾದಗಳು, LDOUBLE);
				ಇಲ್ಲದಿದ್ದರೆ
					fvalue = va_arg (ವಾದಗಳು, ದ್ವಿಗುಣ);
				ಆದರೆ (fmtfp(ಬಫರ್, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ಹೋಗು fail;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'G':
				flags |= DP_F_ಮೇಲೆ;
			ಸ್ಥಿತಿ 'g':
				ಆದರೆ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (ವಾದಗಳು, LDOUBLE);
				ಇಲ್ಲದಿದ್ದರೆ
					fvalue = va_arg (ವಾದಗಳು, ದ್ವಿಗುಣ);
				ಆದರೆ (fmtfp(ಬಫರ್, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ಹೋಗು fail;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'c':
				DOPR_OUTCH(ಬಫರ್, currlen, maxlen,
				    va_arg (ವಾದಗಳು, ಪೂರ್ಣಾಂಕ));
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 's':
				strvalue = va_arg (ವಾದಗಳು, ಅಕ್ಷರ *);
				ಆದರೆ (!strvalue) strvalue = "(NULL)";
				ಆದರೆ (max == -1) {
					max = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(strvalue);
				}
				ಆದರೆ (min > 0 && max >= 0 && min > max) max = min;
				ಆದರೆ (fmtstr(ಬಫರ್, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					ಹೋಗು fail;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ 'p':
				strvalue = va_arg (ವಾದಗಳು, ಶೂನ್ಯ *);
				ಆದರೆ (fmtint(ಬಫರ್, &currlen, maxlen,
				    (ದೀರ್ಘ) strvalue, 16, min, max, flags) == -1)
					ಹೋಗು fail;
				ನಿಲ್ಲಿಸು;
#ಆದರೆ we_dont_want_this_ಒಳ_openssh
			ಸ್ಥಿತಿ 'n':
				ಆದರೆ (cflags == DP_C_SHORT) {
					ಗಿಡ್ಡ ಪೂರ್ಣಾಂಕ *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (ವಾದಗಳು, ಗಿಡ್ಡ ಪೂರ್ಣಾಂಕ *);
					*ಅಂಕೆ = currlen;
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_LONG) {
					ದೀರ್ಘ ಪೂರ್ಣಾಂಕ *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (ವಾದಗಳು, ದೀರ್ಘ ಪೂರ್ಣಾಂಕ *);
					*ಅಂಕೆ = (ದೀರ್ಘ ಪೂರ್ಣಾಂಕ)currlen;
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_LLONG) {
					LLONG *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (ವಾದಗಳು, LLONG *);
					*ಅಂಕೆ = (LLONG)currlen;
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_ಗಾತ್ರ) {
					ssize_t *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (ವಾದಗಳು, ssize_t *);
					*ಅಂಕೆ = (ssize_t)currlen;
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cflags == DP_C_INTMAX) {
					intmax_t *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (ವಾದಗಳು, intmax_t *);
					*ಅಂಕೆ = (intmax_t)currlen;
				} ಇಲ್ಲದಿದ್ದರೆ {
					ಪೂರ್ಣಾಂಕ *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (ವಾದಗಳು, ಪೂರ್ಣಾಂಕ *);
					*ಅಂಕೆ = currlen;
				}
				ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ
			ಸ್ಥಿತಿ '%':
				DOPR_OUTCH(ಬಫರ್, currlen, maxlen, ch);
				ನಿಲ್ಲಿಸು;
			ಪೂರ್ವನಿಯೋಜಿತ:
				/* Unknown, skip */
				ನಿಲ್ಲಿಸು;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ DP_S_ಮುಗಿದ:
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			/* hmm? */
			ನಿಲ್ಲಿಸು; /* some picky compilers need this */
		}
	}
	ಆದರೆ (maxlen != 0) {
		ಆದರೆ (currlen < maxlen - 1)
			ಬಫರ್[currlen] = '\0';
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (maxlen > 0)
			ಬಫರ್[maxlen - 1] = '\0';
	}
	va_end(ವಾದಗಳು);
	ಹಿಂತಿರುಗಿ currlen < ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ ? (ಪೂರ್ಣಾಂಕ)currlen : -1;
 fail:
	va_end(ವಾದಗಳು);
	ಹಿಂತಿರುಗಿ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fmtstr(ಅಕ್ಷರ *ಬಫರ್, ಗಾತ್ರ_t *currlen, ಗಾತ್ರ_t maxlen,
    ಅಕ್ಷರ *ಮೌಲ್ಯ, ಪೂರ್ಣಾಂಕ flags, ಪೂರ್ಣಾಂಕ min, ಪೂರ್ಣಾಂಕ max)
{
	ಪೂರ್ಣಾಂಕ padlen, strln;     /* amount to pad */
	ಪೂರ್ಣಾಂಕ cnt = 0;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SNPRINTF
	ಬರೆ("fmtstr min=%d max=%d s=[%s]\n", min, max, ಮೌಲ್ಯ);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (ಮೌಲ್ಯ == 0) {
		ಮೌಲ್ಯ = "<NULL>";
	}

	ಗಾಗಿ (strln = 0; strln < max && ಮೌಲ್ಯ[strln]; ++strln); /* strlen */
	padlen = min - strln;
	ಆದರೆ (padlen < 0)
		padlen = 0;
	ಆದರೆ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	ಆಗ ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	ಆಗ (*ಮೌಲ್ಯ && (cnt < max)) {
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, *ಮೌಲ್ಯ);
		ಮೌಲ್ಯ++;
		++cnt;
	}
	ಆಗ ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fmtint(ಅಕ್ಷರ *ಬಫರ್, ಗಾತ್ರ_t *currlen, ಗಾತ್ರ_t maxlen,
    intmax_t ಮೌಲ್ಯ, ಪೂರ್ಣಾಂಕ ತಳ, ಪೂರ್ಣಾಂಕ min, ಪೂರ್ಣಾಂಕ max, ಪೂರ್ಣಾಂಕ flags)
{
	ಪೂರ್ಣಾಂಕ signvalue = 0;
	ಚಿಹ್ನೆರಹಿತ LLONG uvalue;
	ಅಕ್ಷರ convert[20];
	ಪೂರ್ಣಾಂಕ ಇರಿಸು = 0;
	ಪೂರ್ಣಾಂಕ spadlen = 0; /* amount to space pad */
	ಪೂರ್ಣಾಂಕ zpadlen = 0; /* amount to zero pad */
	ಪೂರ್ಣಾಂಕ caps = 0;

	ಆದರೆ (max < 0)
		max = 0;

	uvalue = ಮೌಲ್ಯ;

	ಆದರೆ(!(flags & DP_F_UNSIGNED)) {
		ಆದರೆ( ಮೌಲ್ಯ < 0 ) {
			signvalue = '-';
			uvalue = -ಮೌಲ್ಯ;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	ಆದರೆ (flags & DP_F_ಮೇಲೆ) caps = 1; /* Should characters be upper case? */

	ಮಾಡು {
		convert[ಇರಿಸು++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (ಚಿಹ್ನೆರಹಿತ)ತಳ  ];
		uvalue = (uvalue / (ಚಿಹ್ನೆರಹಿತ)ತಳ );
	} ಆಗ(uvalue && (ಇರಿಸು < 20));
	ಆದರೆ (ಇರಿಸು == 20) ಇರಿಸು--;
	convert[ಇರಿಸು] = 0;

	zpadlen = max - ಇರಿಸು;
	spadlen = min - MAX (max, ಇರಿಸು) - (signvalue ? 1 : 0);
	ಆದರೆ (zpadlen < 0) zpadlen = 0;
	ಆದರೆ (spadlen < 0) spadlen = 0;
	ಆದರೆ (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	ಆದರೆ (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SNPRINTF
	ಬರೆ("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, ಇರಿಸು);
#ಆದರೆ_ಅಂತ್ಯ

	/* Spaces */
	ಆಗ (spadlen > 0) {
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	ಆದರೆ (signvalue)
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, signvalue);

	/* Zeros */
	ಆದರೆ (zpadlen > 0) {
		ಆಗ (zpadlen > 0) {
			DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	ಆಗ (ಇರಿಸು > 0) {
		--ಇರಿಸು;
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, convert[ಇರಿಸು]);
	}

	/* Left Justified spaces */
	ಆಗ (spadlen < 0) {
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, ' ');
		++spadlen;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ LDOUBLE abs_val(LDOUBLE ಮೌಲ್ಯ)
{
	LDOUBLE ಫಲಿತಾಂಶ = ಮೌಲ್ಯ;

	ಆದರೆ (ಮೌಲ್ಯ < 0)
		ಫಲಿತಾಂಶ = -ಮೌಲ್ಯ;

	ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

ಸ್ಥಿರ LDOUBLE POW10(ಪೂರ್ಣಾಂಕ val)
{
	LDOUBLE ಫಲಿತಾಂಶ = 1;

	ಆಗ (val) {
		ಫಲಿತಾಂಶ *= 10;
		val--;
	}

	ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

ಸ್ಥಿರ LLONG ಸುತ್ತು_2(LDOUBLE ಮೌಲ್ಯ)
{
	LLONG intpart;

	intpart = (LLONG)ಮೌಲ್ಯ;
	ಮೌಲ್ಯ = ಮೌಲ್ಯ - intpart;
	ಆದರೆ (ಮೌಲ್ಯ >= 0.5) intpart++;

	ಹಿಂತಿರುಗಿ intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
ಸ್ಥಿರ ದ್ವಿಗುಣ my_modf(ದ್ವಿಗುಣ x0, ದ್ವಿಗುಣ *iptr)
{
	ಪೂರ್ಣಾಂಕ i;
	ದೀರ್ಘ l;
	ದ್ವಿಗುಣ x = x0;
	ದ್ವಿಗುಣ f = 1.0;

	ಗಾಗಿ (i=0;i<100;i++) {
		l = (ದೀರ್ಘ)x;
		ಆದರೆ (l <= (x+1) && l >= (x-1)) ನಿಲ್ಲಿಸು;
		x *= 0.1;
		f *= 10.0;
	}

	ಆದರೆ (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ (i != 0) {
		ದ್ವಿಗುಣ i2;
		ದ್ವಿಗುಣ ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		ಹಿಂತಿರುಗಿ ret;
	}

	(*iptr) = l;
	ಹಿಂತಿರುಗಿ x - (*iptr);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fmtfp (ಅಕ್ಷರ *ಬಫರ್, ಗಾತ್ರ_t *currlen, ಗಾತ್ರ_t maxlen,
    LDOUBLE fvalue, ಪೂರ್ಣಾಂಕ min, ಪೂರ್ಣಾಂಕ max, ಪೂರ್ಣಾಂಕ flags)
{
	ಪೂರ್ಣಾಂಕ signvalue = 0;
	ದ್ವಿಗುಣ ufvalue;
	ಅಕ್ಷರ iconvert[311];
	ಅಕ್ಷರ fconvert[311];
	ಪೂರ್ಣಾಂಕ iplace = 0;
	ಪೂರ್ಣಾಂಕ fplace = 0;
	ಪೂರ್ಣಾಂಕ padlen = 0; /* amount to pad */
	ಪೂರ್ಣಾಂಕ zpadlen = 0;
#ಆದರೆ 0
	ಪೂರ್ಣಾಂಕ caps = 0;
#ಆದರೆ_ಅಂತ್ಯ
	ಪೂರ್ಣಾಂಕ idx;
	ದ್ವಿಗುಣ intpart;
	ದ್ವಿಗುಣ fracpart;
	ದ್ವಿಗುಣ ತಾತ್ಕಾಲಿಕ;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	ಆದರೆ (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	ಆದರೆ (fvalue < 0) {
		signvalue = '-';
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#ಆದರೆ 0
	ಆದರೆ (flags & DP_F_ಮೇಲೆ) caps = 1; /* Should characters be upper case? */
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ 0
	 ಆದರೆ (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#ಆದರೆ_ಅಂತ್ಯ

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	ಆದರೆ (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	ತಾತ್ಕಾಲಿಕ = ufvalue;
	my_modf(ತಾತ್ಕಾಲಿಕ, &intpart);

	fracpart = ಸುತ್ತು_2((POW10(max)) * (ufvalue - intpart));

	ಆದರೆ (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	ಮಾಡು {
		ತಾತ್ಕಾಲಿಕ = intpart*0.1;
		my_modf(ತಾತ್ಕಾಲಿಕ, &intpart);
		idx = (ಪೂರ್ಣಾಂಕ) ((ತಾತ್ಕಾಲಿಕ -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} ಆಗ (intpart && (iplace < 311));
	ಆದರೆ (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	ಆದರೆ (fracpart)
	{
		ಮಾಡು {
			ತಾತ್ಕಾಲಿಕ = fracpart*0.1;
			my_modf(ತಾತ್ಕಾಲಿಕ, &fracpart);
			idx = (ಪೂರ್ಣಾಂಕ) ((ತಾತ್ಕಾಲಿಕ -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} ಆಗ(fracpart && (fplace < 311));
		ಆದರೆ (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	ಆದರೆ (zpadlen < 0) zpadlen = 0;
	ಆದರೆ (padlen < 0)
		padlen = 0;
	ಆದರೆ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	ಆದರೆ ((flags & DP_F_ZERO) && (padlen > 0)) {
		ಆದರೆ (signvalue) {
			DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		ಆಗ (padlen > 0) {
			DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, '0');
			--padlen;
		}
	}
	ಆಗ (padlen > 0) {
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, ' ');
		--padlen;
	}
	ಆದರೆ (signvalue)
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, signvalue);

	ಆಗ (iplace > 0) {
		--iplace;
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, iconvert[iplace]);
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SNPRINTF
	ಬರೆ("fmtfp: fplace=%d zpadlen=%d\n", fplace, zpadlen);
#ಆದರೆ_ಅಂತ್ಯ

	/*
	 * Decimal point.  This should probably use locale to find the correct
	 * char to print out.
	 */
	ಆದರೆ (max > 0) {
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, '.');

		ಆಗ (zpadlen > 0) {
			DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, '0');
			--zpadlen;
		}

		ಆಗ (fplace > 0) {
			--fplace;
			DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, fconvert[fplace]);
		}
	}

	ಆಗ (padlen < 0) {
		DOPR_OUTCH(ಬಫರ್, *currlen, maxlen, ' ');
		++padlen;
	}
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#ಆದರೆ !defined(HAVE_VSNPRINTF)
ಪೂರ್ಣಾಂಕ
vsnprintf (ಅಕ್ಷರ *str, ಗಾತ್ರ_t ಎಣಿಕೆ_2, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, va_list ವಾದಗಳು)
{
	ಹಿಂತಿರುಗಿ dopr(str, ಎಣಿಕೆ_2, fmt, ವಾದಗಳು);
}
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(HAVE_SNPRINTF)
ಪೂರ್ಣಾಂಕ
snprintf(ಅಕ್ಷರ *str, ಗಾತ್ರ_t ಎಣಿಕೆ_2, SNPRINTF_CONST ಅಕ್ಷರ *fmt, ...)
{
	ಗಾತ್ರ_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, ಎಣಿಕೆ_2, fmt, ap);
	va_end(ap);
	ಹಿಂತಿರುಗಿ ret;
}
#ಆದರೆ_ಅಂತ್ಯ
