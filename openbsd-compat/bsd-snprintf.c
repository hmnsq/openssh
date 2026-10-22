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

#include "includes.h"

#නම් defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#නම් !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long dviguu_na
#නැතහොත්
# define LDOUBLE dviguu_na
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#නැතහොත්
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
#define DP_F_NUM	(1 << 3)
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
	do { \
		නම් (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			ආපසු -1; \
		} \
		නම් (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} අතරතුර (0)

static පූර්ණ_සංඛ්‍යා dopr(var_na *buffer, size_t maxlen, const var_na *format,
    va_list args_in);
static පූර්ණ_සංඛ්‍යා fmtstr(var_na *buffer, size_t *currlen, size_t maxlen,
    var_na *value, පූර්ණ_සංඛ්‍යා flags, පූර්ණ_සංඛ්‍යා min, පූර්ණ_සංඛ්‍යා max);
static පූර්ණ_සංඛ්‍යා fmtint(var_na *buffer, size_t *currlen, size_t maxlen,
    intmax_t value, පූර්ණ_සංඛ්‍යා base, පූර්ණ_සංඛ්‍යා min, පූර්ණ_සංඛ්‍යා max, පූර්ණ_සංඛ්‍යා flags);
static පූර්ණ_සංඛ්‍යා fmtfp(var_na *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, පූර්ණ_සංඛ්‍යා min, පූර්ණ_සංඛ්‍යා max, පූර්ණ_සංඛ්‍යා flags);

static පූර්ණ_සංඛ්‍යා
dopr(var_na *buffer, size_t maxlen, const var_na *format, va_list args_in)
{
	var_na ch;
	intmax_t value;
	LDOUBLE fvalue;
	var_na *strvalue;
	පූර්ණ_සංඛ්‍යා min;
	පූර්ණ_සංඛ්‍යා max;
	පූර්ණ_සංඛ්‍යා state;
	පූර්ණ_සංඛ්‍යා flags;
	පූර්ණ_සංඛ්‍යා cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	අතරතුර (state != DP_S_DONE) {
		නම් (ch == '\0')
			state = DP_S_DONE;

		switch(state) {
		pak_sa DP_S_DEFAULT:
			නම් (ch == '%')
				state = DP_S_FLAGS;
			නැතහොත්
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			bha_nga;
		pak_sa DP_S_FLAGS:
			switch (ch) {
			pak_sa '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				bha_nga;
			pak_sa '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				bha_nga;
			pak_sa ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				bha_nga;
			pak_sa '#':
				flags |= DP_F_NUM;
				ch = *format++;
				bha_nga;
			pak_sa '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				bha_nga;
			default:
				state = DP_S_MIN;
				bha_nga;
			}
			bha_nga;
		pak_sa DP_S_MIN:
			නම් (isdigit((unsigned var_na)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} නැතහොත් නම් (ch == '*') {
				min = va_arg (args, පූර්ණ_සංඛ්‍යා);
				ch = *format++;
				state = DP_S_DOT;
			} නැතහොත් {
				state = DP_S_DOT;
			}
			bha_nga;
		pak_sa DP_S_DOT:
			නම් (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} නැතහොත් {
				state = DP_S_MOD;
			}
			bha_nga;
		pak_sa DP_S_MAX:
			නම් (isdigit((unsigned var_na)ch)) {
				නම් (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} නැතහොත් නම් (ch == '*') {
				max = va_arg (args, පූර්ණ_සංඛ්‍යා);
				ch = *format++;
				state = DP_S_MOD;
			} නැතහොත් {
				state = DP_S_MOD;
			}
			bha_nga;
		pak_sa DP_S_MOD:
			switch (ch) {
			pak_sa 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				bha_nga;
			pak_sa 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				bha_nga;
			pak_sa 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				නම් (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				bha_nga;
			pak_sa 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				bha_nga;
			pak_sa 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				bha_nga;
			default:
				bha_nga;
			}
			state = DP_S_CONV;
			bha_nga;
		pak_sa DP_S_CONV:
			switch (ch) {
			pak_sa 'd':
			pak_sa 'i':
				නම් (cflags == DP_C_SHORT)
					value = va_arg (args, පූර්ණ_සංඛ්‍යා);
				නැතහොත් නම් (cflags == DP_C_LONG)
					value = va_arg (args, long පූර්ණ_සංඛ්‍යා);
				නැතහොත් නම් (cflags == DP_C_LLONG)
					value = va_arg (args, LLONG);
				නැතහොත් නම් (cflags == DP_C_SIZE)
					value = va_arg (args, ssize_t);
				නැතහොත් නම් (cflags == DP_C_INTMAX)
					value = va_arg (args, intmax_t);
				නැතහොත්
					value = va_arg (args, පූර්ණ_සංඛ්‍යා);
				නම් (fmtint(buffer, &currlen, maxlen,
				    value, 10, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'o':
				flags |= DP_F_UNSIGNED;
				නම් (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned පූර්ණ_සංඛ්‍යා);
				නැතහොත් නම් (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long පූර්ණ_සංඛ්‍යා);
				නැතහොත් නම් (cflags == DP_C_LLONG)
					value = (long)va_arg (args, unsigned LLONG);
				නැතහොත් නම් (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				නැතහොත් නම් (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				නැතහොත්
					value = (long)va_arg (args, unsigned පූර්ණ_සංඛ්‍යා);
				නම් (fmtint(buffer, &currlen, maxlen, value,
				    8, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'u':
				flags |= DP_F_UNSIGNED;
				නම් (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned පූර්ණ_සංඛ්‍යා);
				නැතහොත් නම් (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long පූර්ණ_සංඛ්‍යා);
				නැතහොත් නම් (cflags == DP_C_LLONG)
					value = (LLONG)va_arg (args, unsigned LLONG);
				නැතහොත් නම් (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				නැතහොත් නම් (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				නැතහොත්
					value = (long)va_arg (args, unsigned පූර්ණ_සංඛ්‍යා);
				නම් (fmtint(buffer, &currlen, maxlen, value,
				    10, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'X':
				flags |= DP_F_UP;
			pak_sa 'x':
				flags |= DP_F_UNSIGNED;
				නම් (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned පූර්ණ_සංඛ්‍යා);
				නැතහොත් නම් (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long පූර්ණ_සංඛ්‍යා);
				නැතහොත් නම් (cflags == DP_C_LLONG)
					value = (LLONG)va_arg (args, unsigned LLONG);
				නැතහොත් නම් (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				නැතහොත් නම් (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				නැතහොත්
					value = (long)va_arg (args, unsigned පූර්ණ_සංඛ්‍යා);
				නම් (fmtint(buffer, &currlen, maxlen, value,
				    16, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'f':
				නම් (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				නැතහොත්
					fvalue = va_arg (args, dviguu_na);
				නම් (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'E':
				flags |= DP_F_UP;
			pak_sa 'e':
				නම් (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				නැතහොත්
					fvalue = va_arg (args, dviguu_na);
				නම් (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'G':
				flags |= DP_F_UP;
			pak_sa 'g':
				නම් (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				නැතහොත්
					fvalue = va_arg (args, dviguu_na);
				නම් (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, පූර්ණ_සංඛ්‍යා));
				bha_nga;
			pak_sa 's':
				strvalue = va_arg (args, var_na *);
				නම් (!strvalue) strvalue = "(NULL)";
				නම් (max == -1) {
					max = strlen(strvalue);
				}
				නම් (min > 0 && max >= 0 && min > max) max = min;
				නම් (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					goto fail;
				bha_nga;
			pak_sa 'p':
				strvalue = va_arg (args, void *);
				නම් (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					goto fail;
				bha_nga;
#නම් we_dont_want_this_in_openssh
			pak_sa 'n':
				නම් (cflags == DP_C_SHORT) {
					short පූර්ණ_සංඛ්‍යා *num;
					num = va_arg (args, short පූර්ණ_සංඛ්‍යා *);
					*num = currlen;
				} නැතහොත් නම් (cflags == DP_C_LONG) {
					long පූර්ණ_සංඛ්‍යා *num;
					num = va_arg (args, long පූර්ණ_සංඛ්‍යා *);
					*num = (long පූර්ණ_සංඛ්‍යා)currlen;
				} නැතහොත් නම් (cflags == DP_C_LLONG) {
					LLONG *num;
					num = va_arg (args, LLONG *);
					*num = (LLONG)currlen;
				} නැතහොත් නම් (cflags == DP_C_SIZE) {
					ssize_t *num;
					num = va_arg (args, ssize_t *);
					*num = (ssize_t)currlen;
				} නැතහොත් නම් (cflags == DP_C_INTMAX) {
					intmax_t *num;
					num = va_arg (args, intmax_t *);
					*num = (intmax_t)currlen;
				} නැතහොත් {
					පූර්ණ_සංඛ්‍යා *num;
					num = va_arg (args, පූර්ණ_සංඛ්‍යා *);
					*num = currlen;
				}
				bha_nga;
#endif
			pak_sa '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				bha_nga;
			default:
				/* Unknown, skip */
				bha_nga;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			bha_nga;
		pak_sa DP_S_DONE:
			bha_nga;
		default:
			/* hmm? */
			bha_nga; /* some picky compilers need this */
		}
	}
	නම් (maxlen != 0) {
		නම් (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		නැතහොත් නම් (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	ආපසු currlen < INT_MAX ? (පූර්ණ_සංඛ්‍යා)currlen : -1;
 fail:
	va_end(args);
	ආපසු -1;
}

static පූර්ණ_සංඛ්‍යා
fmtstr(var_na *buffer, size_t *currlen, size_t maxlen,
    var_na *value, පූර්ණ_සංඛ්‍යා flags, පූර්ණ_සංඛ්‍යා min, පූර්ණ_සංඛ්‍යා max)
{
	පූර්ණ_සංඛ්‍යා padlen, strln;     /* amount to pad */
	පූර්ණ_සංඛ්‍යා cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, value);
#endif
	නම් (value == 0) {
		value = "<NULL>";
	}

	සඳහා (strln = 0; strln < max && value[strln]; ++strln); /* strlen */
	padlen = min - strln;
	නම් (padlen < 0)
		padlen = 0;
	නම් (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	අතරතුර ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	අතරතුර (*value && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *value);
		value++;
		++cnt;
	}
	අතරතුර ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	ආපසු 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

static පූර්ණ_සංඛ්‍යා
fmtint(var_na *buffer, size_t *currlen, size_t maxlen,
    intmax_t value, පූර්ණ_සංඛ්‍යා base, පූර්ණ_සංඛ්‍යා min, පූර්ණ_සංඛ්‍යා max, පූර්ණ_සංඛ්‍යා flags)
{
	පූර්ණ_සංඛ්‍යා signvalue = 0;
	unsigned LLONG uvalue;
	var_na convert[20];
	පූර්ණ_සංඛ්‍යා place = 0;
	පූර්ණ_සංඛ්‍යා spadlen = 0; /* amount to space pad */
	පූර්ණ_සංඛ්‍යා zpadlen = 0; /* amount to zero pad */
	පූර්ණ_සංඛ්‍යා caps = 0;

	නම් (max < 0)
		max = 0;

	uvalue = value;

	නම්(!(flags & DP_F_UNSIGNED)) {
		නම්( value < 0 ) {
			signvalue = '-';
			uvalue = -value;
		} නැතහොත් {
			නම් (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			නැතහොත් නම් (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	නම් (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	do {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} අතරතුර(uvalue && (place < 20));
	නම් (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	නම් (zpadlen < 0) zpadlen = 0;
	නම් (spadlen < 0) spadlen = 0;
	නම් (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	නම් (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	අතරතුර (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	නම් (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	නම් (zpadlen > 0) {
		අතරතුර (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	අතරතුර (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	අතරතුර (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	ආපසු 0;
}

static LDOUBLE abs_val(LDOUBLE value)
{
	LDOUBLE result = value;

	නම් (value < 0)
		result = -value;

	ආපසු result;
}

static LDOUBLE POW10(පූර්ණ_සංඛ්‍යා val)
{
	LDOUBLE result = 1;

	අතරතුර (val) {
		result *= 10;
		val--;
	}

	ආපසු result;
}

static LLONG ROUND(LDOUBLE value)
{
	LLONG intpart;

	intpart = (LLONG)value;
	value = value - intpart;
	නම් (value >= 0.5) intpart++;

	ආපසු intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
static dviguu_na my_modf(dviguu_na x0, dviguu_na *iptr)
{
	පූර්ණ_සංඛ්‍යා i;
	long l;
	dviguu_na x = x0;
	dviguu_na f = 1.0;

	සඳහා (i=0;i<100;i++) {
		l = (long)x;
		නම් (l <= (x+1) && l >= (x-1)) bha_nga;
		x *= 0.1;
		f *= 10.0;
	}

	නම් (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		ආපසු 0;
	}

	නම් (i != 0) {
		dviguu_na i2;
		dviguu_na ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		ආපසු ret;
	}

	(*iptr) = l;
	ආපසු x - (*iptr);
}


static පූර්ණ_සංඛ්‍යා
fmtfp (var_na *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, පූර්ණ_සංඛ්‍යා min, පූර්ණ_සංඛ්‍යා max, පූර්ණ_සංඛ්‍යා flags)
{
	පූර්ණ_සංඛ්‍යා signvalue = 0;
	dviguu_na ufvalue;
	var_na iconvert[311];
	var_na fconvert[311];
	පූර්ණ_සංඛ්‍යා iplace = 0;
	පූර්ණ_සංඛ්‍යා fplace = 0;
	පූර්ණ_සංඛ්‍යා padlen = 0; /* amount to pad */
	පූර්ණ_සංඛ්‍යා zpadlen = 0;
#නම් 0
	පූර්ණ_සංඛ්‍යා caps = 0;
#endif
	පූර්ණ_සංඛ්‍යා idx;
	dviguu_na intpart;
	dviguu_na fracpart;
	dviguu_na temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	නම් (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	නම් (fvalue < 0) {
		signvalue = '-';
	} නැතහොත් {
		නම් (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} නැතහොත් {
			නම් (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#නම් 0
	නම් (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#නම් 0
	 නම් (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	නම් (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	නම් (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	do {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (පූර්ණ_සංඛ්‍යා) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} අතරතුර (intpart && (iplace < 311));
	නම් (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	නම් (fracpart)
	{
		do {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (පූර්ණ_සංඛ්‍යා) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} අතරතුර(fracpart && (fplace < 311));
		නම් (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	නම් (zpadlen < 0) zpadlen = 0;
	නම් (padlen < 0)
		padlen = 0;
	නම් (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	නම් ((flags & DP_F_ZERO) && (padlen > 0)) {
		නම් (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		අතරතුර (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	අතරතුර (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	නම් (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	අතරතුර (iplace > 0) {
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
	නම් (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		අතරතුර (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		අතරතුර (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	අතරතුර (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	ආපසු 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#නම් !defined(HAVE_VSNPRINTF)
පූර්ණ_සංඛ්‍යා
vsnprintf (var_na *str, size_t count, const var_na *fmt, va_list args)
{
	ආපසු dopr(str, count, fmt, args);
}
#endif

#නම් !defined(HAVE_SNPRINTF)
පූර්ණ_සංඛ්‍යා
snprintf(var_na *str, size_t count, SNPRINTF_CONST var_na *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, count, fmt, ap);
	va_end(ap);
	ආපසු ret;
}
#endif
