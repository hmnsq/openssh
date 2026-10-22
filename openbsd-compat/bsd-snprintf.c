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

#অন্তর্ভাব "includes.h"

#যদি defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#যদি !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long দ্বিগুণ
#অন্যথা
# define LDOUBLE দ্বিগুণ
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
#define DP_C_আকার    5
#define DP_C_INTMAX  6

#define char_to_int(p) ((p)- '0')
#ifndef MAX
# define MAX(p,q) (((p) >= (q)) ? (p) : (q))
#endif

#define DOPR_OUTCH(buf, pos, buflen, thechar) \
	করো { \
		যদি (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			ফেরত -1; \
		} \
		যদি (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} যখন (0)

স্থির পূর্ণসংখ্যা dopr(অক্ষর *বাফার, আকার_t maxlen, ধ্রুবক অক্ষর *format,
    va_list args_in);
স্থির পূর্ণসংখ্যা fmtstr(অক্ষর *বাফার, আকার_t *currlen, আকার_t maxlen,
    অক্ষর *মান, পূর্ণসংখ্যা flags, পূর্ণসংখ্যা min, পূর্ণসংখ্যা max);
স্থির পূর্ণসংখ্যা fmtint(অক্ষর *বাফার, আকার_t *currlen, আকার_t maxlen,
    intmax_t মান, পূর্ণসংখ্যা base, পূর্ণসংখ্যা min, পূর্ণসংখ্যা max, পূর্ণসংখ্যা flags);
স্থির পূর্ণসংখ্যা fmtfp(অক্ষর *বাফার, আকার_t *currlen, আকার_t maxlen,
    LDOUBLE fvalue, পূর্ণসংখ্যা min, পূর্ণসংখ্যা max, পূর্ণসংখ্যা flags);

স্থির পূর্ণসংখ্যা
dopr(অক্ষর *বাফার, আকার_t maxlen, ধ্রুবক অক্ষর *format, va_list args_in)
{
	অক্ষর ch;
	intmax_t মান;
	LDOUBLE fvalue;
	অক্ষর *strvalue;
	পূর্ণসংখ্যা min;
	পূর্ণসংখ্যা max;
	পূর্ণসংখ্যা state;
	পূর্ণসংখ্যা flags;
	পূর্ণসংখ্যা cflags;
	আকার_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	যখন (state != DP_S_DONE) {
		যদি (ch == '\0')
			state = DP_S_DONE;

		নির্বাচন(state) {
		ক্ষেত্র DP_S_DEFAULT:
			যদি (ch == '%')
				state = DP_S_FLAGS;
			অন্যথা
				DOPR_OUTCH(বাফার, currlen, maxlen, ch);
			ch = *format++;
			বিরতি;
		ক্ষেত্র DP_S_FLAGS:
			নির্বাচন (ch) {
			ক্ষেত্র '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				বিরতি;
			ক্ষেত্র '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				বিরতি;
			ক্ষেত্র ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				বিরতি;
			ক্ষেত্র '#':
				flags |= DP_F_অঙ্ক;
				ch = *format++;
				বিরতি;
			ক্ষেত্র '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				বিরতি;
			পূর্বনির্ধারিত:
				state = DP_S_MIN;
				বিরতি;
			}
			বিরতি;
		ক্ষেত্র DP_S_MIN:
			যদি (isdigit((unsigned অক্ষর)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} অন্যথা যদি (ch == '*') {
				min = va_arg (args, পূর্ণসংখ্যা);
				ch = *format++;
				state = DP_S_DOT;
			} অন্যথা {
				state = DP_S_DOT;
			}
			বিরতি;
		ক্ষেত্র DP_S_DOT:
			যদি (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} অন্যথা {
				state = DP_S_MOD;
			}
			বিরতি;
		ক্ষেত্র DP_S_MAX:
			যদি (isdigit((unsigned অক্ষর)ch)) {
				যদি (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} অন্যথা যদি (ch == '*') {
				max = va_arg (args, পূর্ণসংখ্যা);
				ch = *format++;
				state = DP_S_MOD;
			} অন্যথা {
				state = DP_S_MOD;
			}
			বিরতি;
		ক্ষেত্র DP_S_MOD:
			নির্বাচন (ch) {
			ক্ষেত্র 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				বিরতি;
			ক্ষেত্র 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				বিরতি;
			ক্ষেত্র 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				যদি (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				বিরতি;
			ক্ষেত্র 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				বিরতি;
			ক্ষেত্র 'z':
				cflags = DP_C_আকার;
				ch = *format++;
				বিরতি;
			পূর্বনির্ধারিত:
				বিরতি;
			}
			state = DP_S_CONV;
			বিরতি;
		ক্ষেত্র DP_S_CONV:
			নির্বাচন (ch) {
			ক্ষেত্র 'd':
			ক্ষেত্র 'i':
				যদি (cflags == DP_C_SHORT)
					মান = va_arg (args, পূর্ণসংখ্যা);
				অন্যথা যদি (cflags == DP_C_LONG)
					মান = va_arg (args, long পূর্ণসংখ্যা);
				অন্যথা যদি (cflags == DP_C_LLONG)
					মান = va_arg (args, LLONG);
				অন্যথা যদি (cflags == DP_C_আকার)
					মান = va_arg (args, ssize_t);
				অন্যথা যদি (cflags == DP_C_INTMAX)
					মান = va_arg (args, intmax_t);
				অন্যথা
					মান = va_arg (args, পূর্ণসংখ্যা);
				যদি (fmtint(বাফার, &currlen, maxlen,
				    মান, 10, min, max, flags) == -1)
					যাও fail;
				বিরতি;
			ক্ষেত্র 'o':
				flags |= DP_F_UNSIGNED;
				যদি (cflags == DP_C_SHORT)
					মান = va_arg (args, unsigned পূর্ণসংখ্যা);
				অন্যথা যদি (cflags == DP_C_LONG)
					মান = (long)va_arg (args, unsigned long পূর্ণসংখ্যা);
				অন্যথা যদি (cflags == DP_C_LLONG)
					মান = (long)va_arg (args, unsigned LLONG);
				অন্যথা যদি (cflags == DP_C_আকার)
					মান = va_arg (args, আকার_t);
#ifdef notyet
				অন্যথা যদি (cflags == DP_C_INTMAX)
					মান = va_arg (args, uintmax_t);
#endif
				অন্যথা
					মান = (long)va_arg (args, unsigned পূর্ণসংখ্যা);
				যদি (fmtint(বাফার, &currlen, maxlen, মান,
				    8, min, max, flags) == -1)
					যাও fail;
				বিরতি;
			ক্ষেত্র 'u':
				flags |= DP_F_UNSIGNED;
				যদি (cflags == DP_C_SHORT)
					মান = va_arg (args, unsigned পূর্ণসংখ্যা);
				অন্যথা যদি (cflags == DP_C_LONG)
					মান = (long)va_arg (args, unsigned long পূর্ণসংখ্যা);
				অন্যথা যদি (cflags == DP_C_LLONG)
					মান = (LLONG)va_arg (args, unsigned LLONG);
				অন্যথা যদি (cflags == DP_C_আকার)
					মান = va_arg (args, আকার_t);
#ifdef notyet
				অন্যথা যদি (cflags == DP_C_INTMAX)
					মান = va_arg (args, uintmax_t);
#endif
				অন্যথা
					মান = (long)va_arg (args, unsigned পূর্ণসংখ্যা);
				যদি (fmtint(বাফার, &currlen, maxlen, মান,
				    10, min, max, flags) == -1)
					যাও fail;
				বিরতি;
			ক্ষেত্র 'X':
				flags |= DP_F_UP;
			ক্ষেত্র 'x':
				flags |= DP_F_UNSIGNED;
				যদি (cflags == DP_C_SHORT)
					মান = va_arg (args, unsigned পূর্ণসংখ্যা);
				অন্যথা যদি (cflags == DP_C_LONG)
					মান = (long)va_arg (args, unsigned long পূর্ণসংখ্যা);
				অন্যথা যদি (cflags == DP_C_LLONG)
					মান = (LLONG)va_arg (args, unsigned LLONG);
				অন্যথা যদি (cflags == DP_C_আকার)
					মান = va_arg (args, আকার_t);
#ifdef notyet
				অন্যথা যদি (cflags == DP_C_INTMAX)
					মান = va_arg (args, uintmax_t);
#endif
				অন্যথা
					মান = (long)va_arg (args, unsigned পূর্ণসংখ্যা);
				যদি (fmtint(বাফার, &currlen, maxlen, মান,
				    16, min, max, flags) == -1)
					যাও fail;
				বিরতি;
			ক্ষেত্র 'f':
				যদি (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				অন্যথা
					fvalue = va_arg (args, দ্বিগুণ);
				যদি (fmtfp(বাফার, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					যাও fail;
				বিরতি;
			ক্ষেত্র 'E':
				flags |= DP_F_UP;
			ক্ষেত্র 'e':
				যদি (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				অন্যথা
					fvalue = va_arg (args, দ্বিগুণ);
				যদি (fmtfp(বাফার, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					যাও fail;
				বিরতি;
			ক্ষেত্র 'G':
				flags |= DP_F_UP;
			ক্ষেত্র 'g':
				যদি (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				অন্যথা
					fvalue = va_arg (args, দ্বিগুণ);
				যদি (fmtfp(বাফার, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					যাও fail;
				বিরতি;
			ক্ষেত্র 'c':
				DOPR_OUTCH(বাফার, currlen, maxlen,
				    va_arg (args, পূর্ণসংখ্যা));
				বিরতি;
			ক্ষেত্র 's':
				strvalue = va_arg (args, অক্ষর *);
				যদি (!strvalue) strvalue = "(NULL)";
				যদি (max == -1) {
					max = strlen(strvalue);
				}
				যদি (min > 0 && max >= 0 && min > max) max = min;
				যদি (fmtstr(বাফার, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					যাও fail;
				বিরতি;
			ক্ষেত্র 'p':
				strvalue = va_arg (args, শূন্য *);
				যদি (fmtint(বাফার, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					যাও fail;
				বিরতি;
#যদি we_dont_want_this_in_openssh
			ক্ষেত্র 'n':
				যদি (cflags == DP_C_SHORT) {
					short পূর্ণসংখ্যা *অঙ্ক;
					অঙ্ক = va_arg (args, short পূর্ণসংখ্যা *);
					*অঙ্ক = currlen;
				} অন্যথা যদি (cflags == DP_C_LONG) {
					long পূর্ণসংখ্যা *অঙ্ক;
					অঙ্ক = va_arg (args, long পূর্ণসংখ্যা *);
					*অঙ্ক = (long পূর্ণসংখ্যা)currlen;
				} অন্যথা যদি (cflags == DP_C_LLONG) {
					LLONG *অঙ্ক;
					অঙ্ক = va_arg (args, LLONG *);
					*অঙ্ক = (LLONG)currlen;
				} অন্যথা যদি (cflags == DP_C_আকার) {
					ssize_t *অঙ্ক;
					অঙ্ক = va_arg (args, ssize_t *);
					*অঙ্ক = (ssize_t)currlen;
				} অন্যথা যদি (cflags == DP_C_INTMAX) {
					intmax_t *অঙ্ক;
					অঙ্ক = va_arg (args, intmax_t *);
					*অঙ্ক = (intmax_t)currlen;
				} অন্যথা {
					পূর্ণসংখ্যা *অঙ্ক;
					অঙ্ক = va_arg (args, পূর্ণসংখ্যা *);
					*অঙ্ক = currlen;
				}
				বিরতি;
#endif
			ক্ষেত্র '%':
				DOPR_OUTCH(বাফার, currlen, maxlen, ch);
				বিরতি;
			পূর্বনির্ধারিত:
				/* Unknown, skip */
				বিরতি;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			বিরতি;
		ক্ষেত্র DP_S_DONE:
			বিরতি;
		পূর্বনির্ধারিত:
			/* hmm? */
			বিরতি; /* some picky compilers need this */
		}
	}
	যদি (maxlen != 0) {
		যদি (currlen < maxlen - 1)
			বাফার[currlen] = '\0';
		অন্যথা যদি (maxlen > 0)
			বাফার[maxlen - 1] = '\0';
	}
	va_end(args);
	ফেরত currlen < INT_MAX ? (পূর্ণসংখ্যা)currlen : -1;
 fail:
	va_end(args);
	ফেরত -1;
}

স্থির পূর্ণসংখ্যা
fmtstr(অক্ষর *বাফার, আকার_t *currlen, আকার_t maxlen,
    অক্ষর *মান, পূর্ণসংখ্যা flags, পূর্ণসংখ্যা min, পূর্ণসংখ্যা max)
{
	পূর্ণসংখ্যা padlen, strln;     /* amount to pad */
	পূর্ণসংখ্যা cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, মান);
#endif
	যদি (মান == 0) {
		মান = "<NULL>";
	}

	জন্য (strln = 0; strln < max && মান[strln]; ++strln); /* strlen */
	padlen = min - strln;
	যদি (padlen < 0)
		padlen = 0;
	যদি (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	যখন ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(বাফার, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	যখন (*মান && (cnt < max)) {
		DOPR_OUTCH(বাফার, *currlen, maxlen, *মান);
		মান++;
		++cnt;
	}
	যখন ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(বাফার, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	ফেরত 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

স্থির পূর্ণসংখ্যা
fmtint(অক্ষর *বাফার, আকার_t *currlen, আকার_t maxlen,
    intmax_t মান, পূর্ণসংখ্যা base, পূর্ণসংখ্যা min, পূর্ণসংখ্যা max, পূর্ণসংখ্যা flags)
{
	পূর্ণসংখ্যা signvalue = 0;
	unsigned LLONG uvalue;
	অক্ষর convert[20];
	পূর্ণসংখ্যা place = 0;
	পূর্ণসংখ্যা spadlen = 0; /* amount to space pad */
	পূর্ণসংখ্যা zpadlen = 0; /* amount to zero pad */
	পূর্ণসংখ্যা caps = 0;

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

	করো {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} যখন(uvalue && (place < 20));
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
	যখন (spadlen > 0) {
		DOPR_OUTCH(বাফার, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	যদি (signvalue)
		DOPR_OUTCH(বাফার, *currlen, maxlen, signvalue);

	/* Zeros */
	যদি (zpadlen > 0) {
		যখন (zpadlen > 0) {
			DOPR_OUTCH(বাফার, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	যখন (place > 0) {
		--place;
		DOPR_OUTCH(বাফার, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	যখন (spadlen < 0) {
		DOPR_OUTCH(বাফার, *currlen, maxlen, ' ');
		++spadlen;
	}
	ফেরত 0;
}

স্থির LDOUBLE abs_val(LDOUBLE মান)
{
	LDOUBLE ফলাফল = মান;

	যদি (মান < 0)
		ফলাফল = -মান;

	ফেরত ফলাফল;
}

স্থির LDOUBLE POW10(পূর্ণসংখ্যা val)
{
	LDOUBLE ফলাফল = 1;

	যখন (val) {
		ফলাফল *= 10;
		val--;
	}

	ফেরত ফলাফল;
}

স্থির LLONG ROUND(LDOUBLE মান)
{
	LLONG intpart;

	intpart = (LLONG)মান;
	মান = মান - intpart;
	যদি (মান >= 0.5) intpart++;

	ফেরত intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
স্থির দ্বিগুণ my_modf(দ্বিগুণ x0, দ্বিগুণ *iptr)
{
	পূর্ণসংখ্যা i;
	long l;
	দ্বিগুণ x = x0;
	দ্বিগুণ f = 1.0;

	জন্য (i=0;i<100;i++) {
		l = (long)x;
		যদি (l <= (x+1) && l >= (x-1)) বিরতি;
		x *= 0.1;
		f *= 10.0;
	}

	যদি (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		ফেরত 0;
	}

	যদি (i != 0) {
		দ্বিগুণ i2;
		দ্বিগুণ ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		ফেরত ret;
	}

	(*iptr) = l;
	ফেরত x - (*iptr);
}


স্থির পূর্ণসংখ্যা
fmtfp (অক্ষর *বাফার, আকার_t *currlen, আকার_t maxlen,
    LDOUBLE fvalue, পূর্ণসংখ্যা min, পূর্ণসংখ্যা max, পূর্ণসংখ্যা flags)
{
	পূর্ণসংখ্যা signvalue = 0;
	দ্বিগুণ ufvalue;
	অক্ষর iconvert[311];
	অক্ষর fconvert[311];
	পূর্ণসংখ্যা iplace = 0;
	পূর্ণসংখ্যা fplace = 0;
	পূর্ণসংখ্যা padlen = 0; /* amount to pad */
	পূর্ণসংখ্যা zpadlen = 0;
#যদি 0
	পূর্ণসংখ্যা caps = 0;
#endif
	পূর্ণসংখ্যা idx;
	দ্বিগুণ intpart;
	দ্বিগুণ fracpart;
	দ্বিগুণ অস্থায়ী;

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

	অস্থায়ী = ufvalue;
	my_modf(অস্থায়ী, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	যদি (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	করো {
		অস্থায়ী = intpart*0.1;
		my_modf(অস্থায়ী, &intpart);
		idx = (পূর্ণসংখ্যা) ((অস্থায়ী -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} যখন (intpart && (iplace < 311));
	যদি (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	যদি (fracpart)
	{
		করো {
			অস্থায়ী = fracpart*0.1;
			my_modf(অস্থায়ী, &fracpart);
			idx = (পূর্ণসংখ্যা) ((অস্থায়ী -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} যখন(fracpart && (fplace < 311));
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
			DOPR_OUTCH(বাফার, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		যখন (padlen > 0) {
			DOPR_OUTCH(বাফার, *currlen, maxlen, '0');
			--padlen;
		}
	}
	যখন (padlen > 0) {
		DOPR_OUTCH(বাফার, *currlen, maxlen, ' ');
		--padlen;
	}
	যদি (signvalue)
		DOPR_OUTCH(বাফার, *currlen, maxlen, signvalue);

	যখন (iplace > 0) {
		--iplace;
		DOPR_OUTCH(বাফার, *currlen, maxlen, iconvert[iplace]);
	}

#ifdef DEBUG_SNPRINTF
	printf("fmtfp: fplace=%d zpadlen=%d\n", fplace, zpadlen);
#endif

	/*
	 * Decimal point.  This should probably use locale to find the correct
	 * char to print out.
	 */
	যদি (max > 0) {
		DOPR_OUTCH(বাফার, *currlen, maxlen, '.');

		যখন (zpadlen > 0) {
			DOPR_OUTCH(বাফার, *currlen, maxlen, '0');
			--zpadlen;
		}

		যখন (fplace > 0) {
			--fplace;
			DOPR_OUTCH(বাফার, *currlen, maxlen, fconvert[fplace]);
		}
	}

	যখন (padlen < 0) {
		DOPR_OUTCH(বাফার, *currlen, maxlen, ' ');
		++padlen;
	}
	ফেরত 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#যদি !defined(HAVE_VSNPRINTF)
পূর্ণসংখ্যা
vsnprintf (অক্ষর *str, আকার_t গুনতি, ধ্রুবক অক্ষর *fmt, va_list args)
{
	ফেরত dopr(str, গুনতি, fmt, args);
}
#endif

#যদি !defined(HAVE_SNPRINTF)
পূর্ণসংখ্যা
snprintf(অক্ষর *str, আকার_t গুনতি, SNPRINTF_CONST অক্ষর *fmt, ...)
{
	আকার_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, গুনতি, fmt, ap);
	va_end(ap);
	ফেরত ret;
}
#endif
