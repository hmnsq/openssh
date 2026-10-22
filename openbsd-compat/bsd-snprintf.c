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

#অন্তর্ভাৱ "includes.h"

#যদি defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#যদি !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#অন্তর্ভাৱ <ctype.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long দ্ৱিগুণ
#অন্যথা
# define LDOUBLE দ্ৱিগুণ
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#অন্যথা
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
#define DP_F_অঙ্ক	(1 << 3)
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
	কৰা { \
		যদি (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			ঘূৰাই -1; \
		} \
		যদি (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} যেতিয়ালৈ (0)

স্থির পূর্ণাঙ্ক dopr(ৱর্ণ *buffer, size_t maxlen, ধ্রুৱ ৱর্ণ *format,
    va_list args_in);
স্থির পূর্ণাঙ্ক fmtstr(ৱর্ণ *buffer, size_t *currlen, size_t maxlen,
    ৱর্ণ *মান, পূর্ণাঙ্ক flags, পূর্ণাঙ্ক min, পূর্ণাঙ্ক max);
স্থির পূর্ণাঙ্ক fmtint(ৱর্ণ *buffer, size_t *currlen, size_t maxlen,
    intmax_t মান, পূর্ণাঙ্ক base, পূর্ণাঙ্ক min, পূর্ণাঙ্ক max, পূর্ণাঙ্ক flags);
স্থির পূর্ণাঙ্ক fmtfp(ৱর্ণ *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, পূর্ণাঙ্ক min, পূর্ণাঙ্ক max, পূর্ণাঙ্ক flags);

স্থির পূর্ণাঙ্ক
dopr(ৱর্ণ *buffer, size_t maxlen, ধ্রুৱ ৱর্ণ *format, va_list args_in)
{
	ৱর্ণ ch;
	intmax_t মান;
	LDOUBLE fvalue;
	ৱর্ণ *strvalue;
	পূর্ণাঙ্ক min;
	পূর্ণাঙ্ক max;
	পূর্ণাঙ্ক state;
	পূর্ণাঙ্ক flags;
	পূর্ণাঙ্ক cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	যেতিয়ালৈ (state != DP_S_DONE) {
		যদি (ch == '\0')
			state = DP_S_DONE;

		ৱিকল্প(state) {
		পক্ষ DP_S_DEFAULT:
			যদি (ch == '%')
				state = DP_S_FLAGS;
			অন্যথা
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			ভঙ্গ;
		পক্ষ DP_S_FLAGS:
			ৱিকল্প (ch) {
			পক্ষ '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				ভঙ্গ;
			পক্ষ '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				ভঙ্গ;
			পক্ষ ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				ভঙ্গ;
			পক্ষ '#':
				flags |= DP_F_অঙ্ক;
				ch = *format++;
				ভঙ্গ;
			পক্ষ '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				ভঙ্গ;
			স্ৱভাৱ:
				state = DP_S_MIN;
				ভঙ্গ;
			}
			ভঙ্গ;
		পক্ষ DP_S_MIN:
			যদি (isdigit((unsigned ৱর্ণ)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} অন্যথা যদি (ch == '*') {
				min = va_arg (args, পূর্ণাঙ্ক);
				ch = *format++;
				state = DP_S_DOT;
			} অন্যথা {
				state = DP_S_DOT;
			}
			ভঙ্গ;
		পক্ষ DP_S_DOT:
			যদি (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} অন্যথা {
				state = DP_S_MOD;
			}
			ভঙ্গ;
		পক্ষ DP_S_MAX:
			যদি (isdigit((unsigned ৱর্ণ)ch)) {
				যদি (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} অন্যথা যদি (ch == '*') {
				max = va_arg (args, পূর্ণাঙ্ক);
				ch = *format++;
				state = DP_S_MOD;
			} অন্যথা {
				state = DP_S_MOD;
			}
			ভঙ্গ;
		পক্ষ DP_S_MOD:
			ৱিকল্প (ch) {
			পক্ষ 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				ভঙ্গ;
			পক্ষ 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				ভঙ্গ;
			পক্ষ 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				যদি (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				ভঙ্গ;
			পক্ষ 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				ভঙ্গ;
			পক্ষ 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				ভঙ্গ;
			স্ৱভাৱ:
				ভঙ্গ;
			}
			state = DP_S_CONV;
			ভঙ্গ;
		পক্ষ DP_S_CONV:
			ৱিকল্প (ch) {
			পক্ষ 'd':
			পক্ষ 'i':
				যদি (cflags == DP_C_SHORT)
					মান = va_arg (args, পূর্ণাঙ্ক);
				অন্যথা যদি (cflags == DP_C_LONG)
					মান = va_arg (args, long পূর্ণাঙ্ক);
				অন্যথা যদি (cflags == DP_C_LLONG)
					মান = va_arg (args, LLONG);
				অন্যথা যদি (cflags == DP_C_SIZE)
					মান = va_arg (args, ssize_t);
				অন্যথা যদি (cflags == DP_C_INTMAX)
					মান = va_arg (args, intmax_t);
				অন্যথা
					মান = va_arg (args, পূর্ণাঙ্ক);
				যদি (fmtint(buffer, &currlen, maxlen,
				    মান, 10, min, max, flags) == -1)
					গচ্ছ fail;
				ভঙ্গ;
			পক্ষ 'o':
				flags |= DP_F_UNSIGNED;
				যদি (cflags == DP_C_SHORT)
					মান = va_arg (args, unsigned পূর্ণাঙ্ক);
				অন্যথা যদি (cflags == DP_C_LONG)
					মান = (long)va_arg (args, unsigned long পূর্ণাঙ্ক);
				অন্যথা যদি (cflags == DP_C_LLONG)
					মান = (long)va_arg (args, unsigned LLONG);
				অন্যথা যদি (cflags == DP_C_SIZE)
					মান = va_arg (args, size_t);
#ifdef notyet
				অন্যথা যদি (cflags == DP_C_INTMAX)
					মান = va_arg (args, uintmax_t);
#endif
				অন্যথা
					মান = (long)va_arg (args, unsigned পূর্ণাঙ্ক);
				যদি (fmtint(buffer, &currlen, maxlen, মান,
				    8, min, max, flags) == -1)
					গচ্ছ fail;
				ভঙ্গ;
			পক্ষ 'u':
				flags |= DP_F_UNSIGNED;
				যদি (cflags == DP_C_SHORT)
					মান = va_arg (args, unsigned পূর্ণাঙ্ক);
				অন্যথা যদি (cflags == DP_C_LONG)
					মান = (long)va_arg (args, unsigned long পূর্ণাঙ্ক);
				অন্যথা যদি (cflags == DP_C_LLONG)
					মান = (LLONG)va_arg (args, unsigned LLONG);
				অন্যথা যদি (cflags == DP_C_SIZE)
					মান = va_arg (args, size_t);
#ifdef notyet
				অন্যথা যদি (cflags == DP_C_INTMAX)
					মান = va_arg (args, uintmax_t);
#endif
				অন্যথা
					মান = (long)va_arg (args, unsigned পূর্ণাঙ্ক);
				যদি (fmtint(buffer, &currlen, maxlen, মান,
				    10, min, max, flags) == -1)
					গচ্ছ fail;
				ভঙ্গ;
			পক্ষ 'X':
				flags |= DP_F_UP;
			পক্ষ 'x':
				flags |= DP_F_UNSIGNED;
				যদি (cflags == DP_C_SHORT)
					মান = va_arg (args, unsigned পূর্ণাঙ্ক);
				অন্যথা যদি (cflags == DP_C_LONG)
					মান = (long)va_arg (args, unsigned long পূর্ণাঙ্ক);
				অন্যথা যদি (cflags == DP_C_LLONG)
					মান = (LLONG)va_arg (args, unsigned LLONG);
				অন্যথা যদি (cflags == DP_C_SIZE)
					মান = va_arg (args, size_t);
#ifdef notyet
				অন্যথা যদি (cflags == DP_C_INTMAX)
					মান = va_arg (args, uintmax_t);
#endif
				অন্যথা
					মান = (long)va_arg (args, unsigned পূর্ণাঙ্ক);
				যদি (fmtint(buffer, &currlen, maxlen, মান,
				    16, min, max, flags) == -1)
					গচ্ছ fail;
				ভঙ্গ;
			পক্ষ 'f':
				যদি (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				অন্যথা
					fvalue = va_arg (args, দ্ৱিগুণ);
				যদি (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					গচ্ছ fail;
				ভঙ্গ;
			পক্ষ 'E':
				flags |= DP_F_UP;
			পক্ষ 'e':
				যদি (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				অন্যথা
					fvalue = va_arg (args, দ্ৱিগুণ);
				যদি (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					গচ্ছ fail;
				ভঙ্গ;
			পক্ষ 'G':
				flags |= DP_F_UP;
			পক্ষ 'g':
				যদি (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				অন্যথা
					fvalue = va_arg (args, দ্ৱিগুণ);
				যদি (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					গচ্ছ fail;
				ভঙ্গ;
			পক্ষ 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, পূর্ণাঙ্ক));
				ভঙ্গ;
			পক্ষ 's':
				strvalue = va_arg (args, ৱর্ণ *);
				যদি (!strvalue) strvalue = "(NULL)";
				যদি (max == -1) {
					max = strlen(strvalue);
				}
				যদি (min > 0 && max >= 0 && min > max) max = min;
				যদি (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					গচ্ছ fail;
				ভঙ্গ;
			পক্ষ 'p':
				strvalue = va_arg (args, শূন্য *);
				যদি (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					গচ্ছ fail;
				ভঙ্গ;
#যদি we_dont_want_this_in_openssh
			পক্ষ 'n':
				যদি (cflags == DP_C_SHORT) {
					short পূর্ণাঙ্ক *অঙ্ক;
					অঙ্ক = va_arg (args, short পূর্ণাঙ্ক *);
					*অঙ্ক = currlen;
				} অন্যথা যদি (cflags == DP_C_LONG) {
					long পূর্ণাঙ্ক *অঙ্ক;
					অঙ্ক = va_arg (args, long পূর্ণাঙ্ক *);
					*অঙ্ক = (long পূর্ণাঙ্ক)currlen;
				} অন্যথা যদি (cflags == DP_C_LLONG) {
					LLONG *অঙ্ক;
					অঙ্ক = va_arg (args, LLONG *);
					*অঙ্ক = (LLONG)currlen;
				} অন্যথা যদি (cflags == DP_C_SIZE) {
					ssize_t *অঙ্ক;
					অঙ্ক = va_arg (args, ssize_t *);
					*অঙ্ক = (ssize_t)currlen;
				} অন্যথা যদি (cflags == DP_C_INTMAX) {
					intmax_t *অঙ্ক;
					অঙ্ক = va_arg (args, intmax_t *);
					*অঙ্ক = (intmax_t)currlen;
				} অন্যথা {
					পূর্ণাঙ্ক *অঙ্ক;
					অঙ্ক = va_arg (args, পূর্ণাঙ্ক *);
					*অঙ্ক = currlen;
				}
				ভঙ্গ;
#endif
			পক্ষ '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				ভঙ্গ;
			স্ৱভাৱ:
				/* Unknown, skip */
				ভঙ্গ;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			ভঙ্গ;
		পক্ষ DP_S_DONE:
			ভঙ্গ;
		স্ৱভাৱ:
			/* hmm? */
			ভঙ্গ; /* some picky compilers need this */
		}
	}
	যদি (maxlen != 0) {
		যদি (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		অন্যথা যদি (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	ঘূৰাই currlen < INT_MAX ? (পূর্ণাঙ্ক)currlen : -1;
 fail:
	va_end(args);
	ঘূৰাই -1;
}

স্থির পূর্ণাঙ্ক
fmtstr(ৱর্ণ *buffer, size_t *currlen, size_t maxlen,
    ৱর্ণ *মান, পূর্ণাঙ্ক flags, পূর্ণাঙ্ক min, পূর্ণাঙ্ক max)
{
	পূর্ণাঙ্ক padlen, strln;     /* amount to pad */
	পূর্ণাঙ্ক cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, মান);
#endif
	যদি (মান == 0) {
		মান = "<NULL>";
	}

	বাবে (strln = 0; strln < max && মান[strln]; ++strln); /* strlen */
	padlen = min - strln;
	যদি (padlen < 0)
		padlen = 0;
	যদি (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	যেতিয়ালৈ ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	যেতিয়ালৈ (*মান && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *মান);
		মান++;
		++cnt;
	}
	যেতিয়ালৈ ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	ঘূৰাই 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

স্থির পূর্ণাঙ্ক
fmtint(ৱর্ণ *buffer, size_t *currlen, size_t maxlen,
    intmax_t মান, পূর্ণাঙ্ক base, পূর্ণাঙ্ক min, পূর্ণাঙ্ক max, পূর্ণাঙ্ক flags)
{
	পূর্ণাঙ্ক signvalue = 0;
	unsigned LLONG uvalue;
	ৱর্ণ convert[20];
	পূর্ণাঙ্ক place = 0;
	পূর্ণাঙ্ক spadlen = 0; /* amount to space pad */
	পূর্ণাঙ্ক zpadlen = 0; /* amount to zero pad */
	পূর্ণাঙ্ক caps = 0;

	যদি (max < 0)
		max = 0;

	uvalue = মান;

	যদি(!(flags & DP_F_UNSIGNED)) {
		যদি( মান < 0 ) {
			signvalue = '-';
			uvalue = -মান;
		} অন্যথা {
			যদি (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			অন্যথা যদি (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	যদি (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	কৰা {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} যেতিয়ালৈ(uvalue && (place < 20));
	যদি (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	যদি (zpadlen < 0) zpadlen = 0;
	যদি (spadlen < 0) spadlen = 0;
	যদি (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	যদি (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	যেতিয়ালৈ (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	যদি (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	যদি (zpadlen > 0) {
		যেতিয়ালৈ (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	যেতিয়ালৈ (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	যেতিয়ালৈ (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	ঘূৰাই 0;
}

স্থির LDOUBLE abs_val(LDOUBLE মান)
{
	LDOUBLE result = মান;

	যদি (মান < 0)
		result = -মান;

	ঘূৰাই result;
}

স্থির LDOUBLE POW10(পূর্ণাঙ্ক val)
{
	LDOUBLE result = 1;

	যেতিয়ালৈ (val) {
		result *= 10;
		val--;
	}

	ঘূৰাই result;
}

স্থির LLONG ROUND(LDOUBLE মান)
{
	LLONG intpart;

	intpart = (LLONG)মান;
	মান = মান - intpart;
	যদি (মান >= 0.5) intpart++;

	ঘূৰাই intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
স্থির দ্ৱিগুণ my_modf(দ্ৱিগুণ x0, দ্ৱিগুণ *iptr)
{
	পূর্ণাঙ্ক i;
	long l;
	দ্ৱিগুণ x = x0;
	দ্ৱিগুণ f = 1.0;

	বাবে (i=0;i<100;i++) {
		l = (long)x;
		যদি (l <= (x+1) && l >= (x-1)) ভঙ্গ;
		x *= 0.1;
		f *= 10.0;
	}

	যদি (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		ঘূৰাই 0;
	}

	যদি (i != 0) {
		দ্ৱিগুণ i2;
		দ্ৱিগুণ ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		ঘূৰাই ret;
	}

	(*iptr) = l;
	ঘূৰাই x - (*iptr);
}


স্থির পূর্ণাঙ্ক
fmtfp (ৱর্ণ *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, পূর্ণাঙ্ক min, পূর্ণাঙ্ক max, পূর্ণাঙ্ক flags)
{
	পূর্ণাঙ্ক signvalue = 0;
	দ্ৱিগুণ ufvalue;
	ৱর্ণ iconvert[311];
	ৱর্ণ fconvert[311];
	পূর্ণাঙ্ক iplace = 0;
	পূর্ণাঙ্ক fplace = 0;
	পূর্ণাঙ্ক padlen = 0; /* amount to pad */
	পূর্ণাঙ্ক zpadlen = 0;
#যদি 0
	পূর্ণাঙ্ক caps = 0;
#endif
	পূর্ণাঙ্ক idx;
	দ্ৱিগুণ intpart;
	দ্ৱিগুণ fracpart;
	দ্ৱিগুণ temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	যদি (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	যদি (fvalue < 0) {
		signvalue = '-';
	} অন্যথা {
		যদি (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} অন্যথা {
			যদি (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#যদি 0
	যদি (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#যদি 0
	 যদি (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	যদি (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	যদি (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	কৰা {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (পূর্ণাঙ্ক) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} যেতিয়ালৈ (intpart && (iplace < 311));
	যদি (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	যদি (fracpart)
	{
		কৰা {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (পূর্ণাঙ্ক) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} যেতিয়ালৈ(fracpart && (fplace < 311));
		যদি (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	যদি (zpadlen < 0) zpadlen = 0;
	যদি (padlen < 0)
		padlen = 0;
	যদি (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	যদি ((flags & DP_F_ZERO) && (padlen > 0)) {
		যদি (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		যেতিয়ালৈ (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	যেতিয়ালৈ (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	যদি (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	যেতিয়ালৈ (iplace > 0) {
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
	যদি (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		যেতিয়ালৈ (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		যেতিয়ালৈ (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	যেতিয়ালৈ (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	ঘূৰাই 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#যদি !defined(HAVE_VSNPRINTF)
পূর্ণাঙ্ক
vsnprintf (ৱর্ণ *str, size_t গুনতি, ধ্রুৱ ৱর্ণ *fmt, va_list args)
{
	ঘূৰাই dopr(str, গুনতি, fmt, args);
}
#endif

#যদি !defined(HAVE_SNPRINTF)
পূর্ণাঙ্ক
snprintf(ৱর্ণ *str, size_t গুনতি, SNPRINTF_CONST ৱর্ণ *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, গুনতি, fmt, ap);
	va_end(ap);
	ঘূৰাই ret;
}
#endif
