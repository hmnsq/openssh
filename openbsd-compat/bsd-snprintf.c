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

#ಯದಿ defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#ಯದಿ !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long ದ್ವಿಗುಣ
#ಅನ್ಯಥಾ
# define LDOUBLE ದ್ವಿಗುಣ
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#ಅನ್ಯಥಾ
# define LLONG long
#endif

/*
 * dopr(): poor man's version of doprintf
 */

/* format read states */
#define DP_S_DEFAULT 0
#define DP_S_FLAGS   1
#define DP_S_MIN     2
#define DP_S_DOT     3
#define DP_S_MAX     4
#define DP_S_MOD     5
#define DP_S_CONV    6
#define DP_S_DONE    7

/* format flags - Bits */
#define DP_F_MINUS	(1 << 0)
#define DP_F_PLUS	(1 << 1)
#define DP_F_SPACE	(1 << 2)
#define DP_F_ಅಂಕೆ	(1 << 3)
#define DP_F_ZERO	(1 << 4)
#define DP_F_UP		(1 << 5)
#define DP_F_UNSIGNED	(1 << 6)

/* Conversion Flags */
#define DP_C_SHORT   1
#define DP_C_LONG    2
#define DP_C_LDOUBLE 3
#define DP_C_LLONG   4
#define DP_C_SIZE    5
#define DP_C_INTMAX  6

#define char_to_int(p) ((p)- '0')
#ifndef MAX
# define MAX(p,q) (((p) >= (q)) ? (p) : (q))
#endif

#define DOPR_OUTCH(buf, pos, buflen, thechar) \
	ಕುರು { \
		ಯದಿ (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			ಪ್ರತ್ಯಾಗಮ -1; \
		} \
		ಯದಿ (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} ಯಾವತ್ (0)

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ dopr(ವರ್ಣ *buffer, size_t maxlen, ಧ್ರುವ ವರ್ಣ *format,
    va_list args_in);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ fmtstr(ವರ್ಣ *buffer, size_t *currlen, size_t maxlen,
    ವರ್ಣ *ಮೌಲ್ಯ, ಪೂರ್ಣಾಙ್ಕ flags, ಪೂರ್ಣಾಙ್ಕ min, ಪೂರ್ಣಾಙ್ಕ max);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ fmtint(ವರ್ಣ *buffer, size_t *currlen, size_t maxlen,
    intmax_t ಮೌಲ್ಯ, ಪೂರ್ಣಾಙ್ಕ base, ಪೂರ್ಣಾಙ್ಕ min, ಪೂರ್ಣಾಙ್ಕ max, ಪೂರ್ಣಾಙ್ಕ flags);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ fmtfp(ವರ್ಣ *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, ಪೂರ್ಣಾಙ್ಕ min, ಪೂರ್ಣಾಙ್ಕ max, ಪೂರ್ಣಾಙ್ಕ flags);

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
dopr(ವರ್ಣ *buffer, size_t maxlen, ಧ್ರುವ ವರ್ಣ *format, va_list args_in)
{
	ವರ್ಣ ch;
	intmax_t ಮೌಲ್ಯ;
	LDOUBLE fvalue;
	ವರ್ಣ *strvalue;
	ಪೂರ್ಣಾಙ್ಕ min;
	ಪೂರ್ಣಾಙ್ಕ max;
	ಪೂರ್ಣಾಙ್ಕ state;
	ಪೂರ್ಣಾಙ್ಕ flags;
	ಪೂರ್ಣಾಙ್ಕ cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	ಯಾವತ್ (state != DP_S_DONE) {
		ಯದಿ (ch == '\0')
			state = DP_S_DONE;

		ವಿಕಲ್ಪ(state) {
		ಪಕ್ಷ DP_S_DEFAULT:
			ಯದಿ (ch == '%')
				state = DP_S_FLAGS;
			ಅನ್ಯಥಾ
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			ಭಙ್ಗ;
		ಪಕ್ಷ DP_S_FLAGS:
			ವಿಕಲ್ಪ (ch) {
			ಪಕ್ಷ '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				ಭಙ್ಗ;
			ಪಕ್ಷ '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				ಭಙ್ಗ;
			ಪಕ್ಷ ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				ಭಙ್ಗ;
			ಪಕ್ಷ '#':
				flags |= DP_F_ಅಂಕೆ;
				ch = *format++;
				ಭಙ್ಗ;
			ಪಕ್ಷ '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				ಭಙ್ಗ;
			ಸ್ವಭಾವ:
				state = DP_S_MIN;
				ಭಙ್ಗ;
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ DP_S_MIN:
			ಯದಿ (isdigit((unsigned ವರ್ಣ)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} ಅನ್ಯಥಾ ಯದಿ (ch == '*') {
				min = va_arg (args, ಪೂರ್ಣಾಙ್ಕ);
				ch = *format++;
				state = DP_S_DOT;
			} ಅನ್ಯಥಾ {
				state = DP_S_DOT;
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ DP_S_DOT:
			ಯದಿ (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} ಅನ್ಯಥಾ {
				state = DP_S_MOD;
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ DP_S_MAX:
			ಯದಿ (isdigit((unsigned ವರ್ಣ)ch)) {
				ಯದಿ (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} ಅನ್ಯಥಾ ಯದಿ (ch == '*') {
				max = va_arg (args, ಪೂರ್ಣಾಙ್ಕ);
				ch = *format++;
				state = DP_S_MOD;
			} ಅನ್ಯಥಾ {
				state = DP_S_MOD;
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ DP_S_MOD:
			ವಿಕಲ್ಪ (ch) {
			ಪಕ್ಷ 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				ಯದಿ (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				ಭಙ್ಗ;
			ಪಕ್ಷ 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				ಭಙ್ಗ;
			ಸ್ವಭಾವ:
				ಭಙ್ಗ;
			}
			state = DP_S_CONV;
			ಭಙ್ಗ;
		ಪಕ್ಷ DP_S_CONV:
			ವಿಕಲ್ಪ (ch) {
			ಪಕ್ಷ 'd':
			ಪಕ್ಷ 'i':
				ಯದಿ (cflags == DP_C_SHORT)
					ಮೌಲ್ಯ = va_arg (args, ಪೂರ್ಣಾಙ್ಕ);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_LONG)
					ಮೌಲ್ಯ = va_arg (args, long ಪೂರ್ಣಾಙ್ಕ);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_LLONG)
					ಮೌಲ್ಯ = va_arg (args, LLONG);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_SIZE)
					ಮೌಲ್ಯ = va_arg (args, ssize_t);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_INTMAX)
					ಮೌಲ್ಯ = va_arg (args, intmax_t);
				ಅನ್ಯಥಾ
					ಮೌಲ್ಯ = va_arg (args, ಪೂರ್ಣಾಙ್ಕ);
				ಯದಿ (fmtint(buffer, &currlen, maxlen,
				    ಮೌಲ್ಯ, 10, min, max, flags) == -1)
					ಗಚ್ಛ fail;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'o':
				flags |= DP_F_UNSIGNED;
				ಯದಿ (cflags == DP_C_SHORT)
					ಮೌಲ್ಯ = va_arg (args, unsigned ಪೂರ್ಣಾಙ್ಕ);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_LONG)
					ಮೌಲ್ಯ = (long)va_arg (args, unsigned long ಪೂರ್ಣಾಙ್ಕ);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_LLONG)
					ಮೌಲ್ಯ = (long)va_arg (args, unsigned LLONG);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_SIZE)
					ಮೌಲ್ಯ = va_arg (args, size_t);
#ifdef notyet
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_INTMAX)
					ಮೌಲ್ಯ = va_arg (args, uintmax_t);
#endif
				ಅನ್ಯಥಾ
					ಮೌಲ್ಯ = (long)va_arg (args, unsigned ಪೂರ್ಣಾಙ್ಕ);
				ಯದಿ (fmtint(buffer, &currlen, maxlen, ಮೌಲ್ಯ,
				    8, min, max, flags) == -1)
					ಗಚ್ಛ fail;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'u':
				flags |= DP_F_UNSIGNED;
				ಯದಿ (cflags == DP_C_SHORT)
					ಮೌಲ್ಯ = va_arg (args, unsigned ಪೂರ್ಣಾಙ್ಕ);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_LONG)
					ಮೌಲ್ಯ = (long)va_arg (args, unsigned long ಪೂರ್ಣಾಙ್ಕ);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_LLONG)
					ಮೌಲ್ಯ = (LLONG)va_arg (args, unsigned LLONG);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_SIZE)
					ಮೌಲ್ಯ = va_arg (args, size_t);
#ifdef notyet
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_INTMAX)
					ಮೌಲ್ಯ = va_arg (args, uintmax_t);
#endif
				ಅನ್ಯಥಾ
					ಮೌಲ್ಯ = (long)va_arg (args, unsigned ಪೂರ್ಣಾಙ್ಕ);
				ಯದಿ (fmtint(buffer, &currlen, maxlen, ಮೌಲ್ಯ,
				    10, min, max, flags) == -1)
					ಗಚ್ಛ fail;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'X':
				flags |= DP_F_UP;
			ಪಕ್ಷ 'x':
				flags |= DP_F_UNSIGNED;
				ಯದಿ (cflags == DP_C_SHORT)
					ಮೌಲ್ಯ = va_arg (args, unsigned ಪೂರ್ಣಾಙ್ಕ);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_LONG)
					ಮೌಲ್ಯ = (long)va_arg (args, unsigned long ಪೂರ್ಣಾಙ್ಕ);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_LLONG)
					ಮೌಲ್ಯ = (LLONG)va_arg (args, unsigned LLONG);
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_SIZE)
					ಮೌಲ್ಯ = va_arg (args, size_t);
#ifdef notyet
				ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_INTMAX)
					ಮೌಲ್ಯ = va_arg (args, uintmax_t);
#endif
				ಅನ್ಯಥಾ
					ಮೌಲ್ಯ = (long)va_arg (args, unsigned ಪೂರ್ಣಾಙ್ಕ);
				ಯದಿ (fmtint(buffer, &currlen, maxlen, ಮೌಲ್ಯ,
				    16, min, max, flags) == -1)
					ಗಚ್ಛ fail;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'f':
				ಯದಿ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				ಅನ್ಯಥಾ
					fvalue = va_arg (args, ದ್ವಿಗುಣ);
				ಯದಿ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ಗಚ್ಛ fail;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'E':
				flags |= DP_F_UP;
			ಪಕ್ಷ 'e':
				ಯದಿ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				ಅನ್ಯಥಾ
					fvalue = va_arg (args, ದ್ವಿಗುಣ);
				ಯದಿ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ಗಚ್ಛ fail;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'G':
				flags |= DP_F_UP;
			ಪಕ್ಷ 'g':
				ಯದಿ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				ಅನ್ಯಥಾ
					fvalue = va_arg (args, ದ್ವಿಗುಣ);
				ಯದಿ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ಗಚ್ಛ fail;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, ಪೂರ್ಣಾಙ್ಕ));
				ಭಙ್ಗ;
			ಪಕ್ಷ 's':
				strvalue = va_arg (args, ವರ್ಣ *);
				ಯದಿ (!strvalue) strvalue = "(NULL)";
				ಯದಿ (max == -1) {
					max = strlen(strvalue);
				}
				ಯದಿ (min > 0 && max >= 0 && min > max) max = min;
				ಯದಿ (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					ಗಚ್ಛ fail;
				ಭಙ್ಗ;
			ಪಕ್ಷ 'p':
				strvalue = va_arg (args, ಶೂನ್ಯ *);
				ಯದಿ (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					ಗಚ್ಛ fail;
				ಭಙ್ಗ;
#ಯದಿ we_dont_want_this_in_openssh
			ಪಕ್ಷ 'n':
				ಯದಿ (cflags == DP_C_SHORT) {
					short ಪೂರ್ಣಾಙ್ಕ *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (args, short ಪೂರ್ಣಾಙ್ಕ *);
					*ಅಂಕೆ = currlen;
				} ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_LONG) {
					long ಪೂರ್ಣಾಙ್ಕ *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (args, long ಪೂರ್ಣಾಙ್ಕ *);
					*ಅಂಕೆ = (long ಪೂರ್ಣಾಙ್ಕ)currlen;
				} ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_LLONG) {
					LLONG *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (args, LLONG *);
					*ಅಂಕೆ = (LLONG)currlen;
				} ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_SIZE) {
					ssize_t *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (args, ssize_t *);
					*ಅಂಕೆ = (ssize_t)currlen;
				} ಅನ್ಯಥಾ ಯದಿ (cflags == DP_C_INTMAX) {
					intmax_t *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (args, intmax_t *);
					*ಅಂಕೆ = (intmax_t)currlen;
				} ಅನ್ಯಥಾ {
					ಪೂರ್ಣಾಙ್ಕ *ಅಂಕೆ;
					ಅಂಕೆ = va_arg (args, ಪೂರ್ಣಾಙ್ಕ *);
					*ಅಂಕೆ = currlen;
				}
				ಭಙ್ಗ;
#endif
			ಪಕ್ಷ '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				ಭಙ್ಗ;
			ಸ್ವಭಾವ:
				/* Unknown, skip */
				ಭಙ್ಗ;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			ಭಙ್ಗ;
		ಪಕ್ಷ DP_S_DONE:
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			/* hmm? */
			ಭಙ್ಗ; /* some picky compilers need this */
		}
	}
	ಯದಿ (maxlen != 0) {
		ಯದಿ (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		ಅನ್ಯಥಾ ಯದಿ (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	ಪ್ರತ್ಯಾಗಮ currlen < INT_MAX ? (ಪೂರ್ಣಾಙ್ಕ)currlen : -1;
 fail:
	va_end(args);
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fmtstr(ವರ್ಣ *buffer, size_t *currlen, size_t maxlen,
    ವರ್ಣ *ಮೌಲ್ಯ, ಪೂರ್ಣಾಙ್ಕ flags, ಪೂರ್ಣಾಙ್ಕ min, ಪೂರ್ಣಾಙ್ಕ max)
{
	ಪೂರ್ಣಾಙ್ಕ padlen, strln;     /* amount to pad */
	ಪೂರ್ಣಾಙ್ಕ cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, ಮೌಲ್ಯ);
#endif
	ಯದಿ (ಮೌಲ್ಯ == 0) {
		ಮೌಲ್ಯ = "<NULL>";
	}

	ಪ್ರತಿ (strln = 0; strln < max && ಮೌಲ್ಯ[strln]; ++strln); /* strlen */
	padlen = min - strln;
	ಯದಿ (padlen < 0)
		padlen = 0;
	ಯದಿ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	ಯಾವತ್ ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	ಯಾವತ್ (*ಮೌಲ್ಯ && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *ಮೌಲ್ಯ);
		ಮೌಲ್ಯ++;
		++cnt;
	}
	ಯಾವತ್ ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fmtint(ವರ್ಣ *buffer, size_t *currlen, size_t maxlen,
    intmax_t ಮೌಲ್ಯ, ಪೂರ್ಣಾಙ್ಕ base, ಪೂರ್ಣಾಙ್ಕ min, ಪೂರ್ಣಾಙ್ಕ max, ಪೂರ್ಣಾಙ್ಕ flags)
{
	ಪೂರ್ಣಾಙ್ಕ signvalue = 0;
	unsigned LLONG uvalue;
	ವರ್ಣ convert[20];
	ಪೂರ್ಣಾಙ್ಕ place = 0;
	ಪೂರ್ಣಾಙ್ಕ spadlen = 0; /* amount to space pad */
	ಪೂರ್ಣಾಙ್ಕ zpadlen = 0; /* amount to zero pad */
	ಪೂರ್ಣಾಙ್ಕ caps = 0;

	ಯದಿ (max < 0)
		max = 0;

	uvalue = ಮೌಲ್ಯ;

	ಯದಿ(!(flags & DP_F_UNSIGNED)) {
		ಯದಿ( ಮೌಲ್ಯ < 0 ) {
			signvalue = '-';
			uvalue = -ಮೌಲ್ಯ;
		} ಅನ್ಯಥಾ {
			ಯದಿ (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			ಅನ್ಯಥಾ ಯದಿ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	ಯದಿ (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	ಕುರು {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} ಯಾವತ್(uvalue && (place < 20));
	ಯದಿ (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	ಯದಿ (zpadlen < 0) zpadlen = 0;
	ಯದಿ (spadlen < 0) spadlen = 0;
	ಯದಿ (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	ಯದಿ (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	ಯಾವತ್ (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	ಯದಿ (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	ಯದಿ (zpadlen > 0) {
		ಯಾವತ್ (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	ಯಾವತ್ (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	ಯಾವತ್ (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ LDOUBLE abs_val(LDOUBLE ಮೌಲ್ಯ)
{
	LDOUBLE result = ಮೌಲ್ಯ;

	ಯದಿ (ಮೌಲ್ಯ < 0)
		result = -ಮೌಲ್ಯ;

	ಪ್ರತ್ಯಾಗಮ result;
}

ಸ್ಥಿರ LDOUBLE POW10(ಪೂರ್ಣಾಙ್ಕ val)
{
	LDOUBLE result = 1;

	ಯಾವತ್ (val) {
		result *= 10;
		val--;
	}

	ಪ್ರತ್ಯಾಗಮ result;
}

ಸ್ಥಿರ LLONG ROUND(LDOUBLE ಮೌಲ್ಯ)
{
	LLONG intpart;

	intpart = (LLONG)ಮೌಲ್ಯ;
	ಮೌಲ್ಯ = ಮೌಲ್ಯ - intpart;
	ಯದಿ (ಮೌಲ್ಯ >= 0.5) intpart++;

	ಪ್ರತ್ಯಾಗಮ intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
ಸ್ಥಿರ ದ್ವಿಗುಣ my_modf(ದ್ವಿಗುಣ x0, ದ್ವಿಗುಣ *iptr)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	long l;
	ದ್ವಿಗುಣ x = x0;
	ದ್ವಿಗುಣ f = 1.0;

	ಪ್ರತಿ (i=0;i<100;i++) {
		l = (long)x;
		ಯದಿ (l <= (x+1) && l >= (x-1)) ಭಙ್ಗ;
		x *= 0.1;
		f *= 10.0;
	}

	ಯದಿ (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ (i != 0) {
		ದ್ವಿಗುಣ i2;
		ದ್ವಿಗುಣ ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		ಪ್ರತ್ಯಾಗಮ ret;
	}

	(*iptr) = l;
	ಪ್ರತ್ಯಾಗಮ x - (*iptr);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fmtfp (ವರ್ಣ *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, ಪೂರ್ಣಾಙ್ಕ min, ಪೂರ್ಣಾಙ್ಕ max, ಪೂರ್ಣಾಙ್ಕ flags)
{
	ಪೂರ್ಣಾಙ್ಕ signvalue = 0;
	ದ್ವಿಗುಣ ufvalue;
	ವರ್ಣ iconvert[311];
	ವರ್ಣ fconvert[311];
	ಪೂರ್ಣಾಙ್ಕ iplace = 0;
	ಪೂರ್ಣಾಙ್ಕ fplace = 0;
	ಪೂರ್ಣಾಙ್ಕ padlen = 0; /* amount to pad */
	ಪೂರ್ಣಾಙ್ಕ zpadlen = 0;
#ಯದಿ 0
	ಪೂರ್ಣಾಙ್ಕ caps = 0;
#endif
	ಪೂರ್ಣಾಙ್ಕ idx;
	ದ್ವಿಗುಣ intpart;
	ದ್ವಿಗುಣ fracpart;
	ದ್ವಿಗುಣ temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	ಯದಿ (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	ಯದಿ (fvalue < 0) {
		signvalue = '-';
	} ಅನ್ಯಥಾ {
		ಯದಿ (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} ಅನ್ಯಥಾ {
			ಯದಿ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#ಯದಿ 0
	ಯದಿ (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#ಯದಿ 0
	 ಯದಿ (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	ಯದಿ (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	ಯದಿ (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	ಕುರು {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (ಪೂರ್ಣಾಙ್ಕ) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} ಯಾವತ್ (intpart && (iplace < 311));
	ಯದಿ (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	ಯದಿ (fracpart)
	{
		ಕುರು {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (ಪೂರ್ಣಾಙ್ಕ) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} ಯಾವತ್(fracpart && (fplace < 311));
		ಯದಿ (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	ಯದಿ (zpadlen < 0) zpadlen = 0;
	ಯದಿ (padlen < 0)
		padlen = 0;
	ಯದಿ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	ಯದಿ ((flags & DP_F_ZERO) && (padlen > 0)) {
		ಯದಿ (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		ಯಾವತ್ (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	ಯಾವತ್ (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	ಯದಿ (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	ಯಾವತ್ (iplace > 0) {
		--iplace;
		DOPR_OUTCH(buffer, *currlen, maxlen, iconvert[iplace]);
	}

#ifdef DEBUG_SNPRINTF
	printf("fmtfp: fplace=%d zpadlen=%d\n", fplace, zpadlen);
#endif

	/*
	 * Decimal point.  This should probably use locale to find the correct
	 * char to print out.
	 */
	ಯದಿ (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		ಯಾವತ್ (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		ಯಾವತ್ (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	ಯಾವತ್ (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#ಯದಿ !defined(HAVE_VSNPRINTF)
ಪೂರ್ಣಾಙ್ಕ
vsnprintf (ವರ್ಣ *str, size_t ಎಣಿಕೆ, ಧ್ರುವ ವರ್ಣ *fmt, va_list args)
{
	ಪ್ರತ್ಯಾಗಮ dopr(str, ಎಣಿಕೆ, fmt, args);
}
#endif

#ಯದಿ !defined(HAVE_SNPRINTF)
ಪೂರ್ಣಾಙ್ಕ
snprintf(ವರ್ಣ *str, size_t ಎಣಿಕೆ, SNPRINTF_CONST ವರ್ಣ *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, ಎಣಿಕೆ, fmt, ap);
	va_end(ap);
	ಪ್ರತ್ಯಾಗಮ ret;
}
#endif
