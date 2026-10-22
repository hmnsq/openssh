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

#အကယ်၍ defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#အကယ်၍ !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long dviguu_na
#မဟုတ်ပါက
# define LDOUBLE dviguu_na
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#မဟုတ်ပါက
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
		အကယ်၍ (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			ပြန်ပေး -1; \
		} \
		အကယ်၍ (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} နေစဉ် (0)

static ကိန်းပြည့် dopr(var_na *buffer, size_t maxlen, const var_na *format,
    va_list args_in);
static ကိန်းပြည့် fmtstr(var_na *buffer, size_t *currlen, size_t maxlen,
    var_na *value, ကိန်းပြည့် flags, ကိန်းပြည့် min, ကိန်းပြည့် max);
static ကိန်းပြည့် fmtint(var_na *buffer, size_t *currlen, size_t maxlen,
    intmax_t value, ကိန်းပြည့် base, ကိန်းပြည့် min, ကိန်းပြည့် max, ကိန်းပြည့် flags);
static ကိန်းပြည့် fmtfp(var_na *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, ကိန်းပြည့် min, ကိန်းပြည့် max, ကိန်းပြည့် flags);

static ကိန်းပြည့်
dopr(var_na *buffer, size_t maxlen, const var_na *format, va_list args_in)
{
	var_na ch;
	intmax_t value;
	LDOUBLE fvalue;
	var_na *strvalue;
	ကိန်းပြည့် min;
	ကိန်းပြည့် max;
	ကိန်းပြည့် state;
	ကိန်းပြည့် flags;
	ကိန်းပြည့် cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	နေစဉ် (state != DP_S_DONE) {
		အကယ်၍ (ch == '\0')
			state = DP_S_DONE;

		switch(state) {
		pak_sa DP_S_DEFAULT:
			အကယ်၍ (ch == '%')
				state = DP_S_FLAGS;
			မဟုတ်ပါက
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
			အကယ်၍ (isdigit((unsigned var_na)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} မဟုတ်ပါက အကယ်၍ (ch == '*') {
				min = va_arg (args, ကိန်းပြည့်);
				ch = *format++;
				state = DP_S_DOT;
			} မဟုတ်ပါက {
				state = DP_S_DOT;
			}
			bha_nga;
		pak_sa DP_S_DOT:
			အကယ်၍ (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} မဟုတ်ပါက {
				state = DP_S_MOD;
			}
			bha_nga;
		pak_sa DP_S_MAX:
			အကယ်၍ (isdigit((unsigned var_na)ch)) {
				အကယ်၍ (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} မဟုတ်ပါက အကယ်၍ (ch == '*') {
				max = va_arg (args, ကိန်းပြည့်);
				ch = *format++;
				state = DP_S_MOD;
			} မဟုတ်ပါက {
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
				အကယ်၍ (ch == 'l') {	/* It's a long long */
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
				အကယ်၍ (cflags == DP_C_SHORT)
					value = va_arg (args, ကိန်းပြည့်);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_LONG)
					value = va_arg (args, long ကိန်းပြည့်);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_LLONG)
					value = va_arg (args, LLONG);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_SIZE)
					value = va_arg (args, ssize_t);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_INTMAX)
					value = va_arg (args, intmax_t);
				မဟုတ်ပါက
					value = va_arg (args, ကိန်းပြည့်);
				အကယ်၍ (fmtint(buffer, &currlen, maxlen,
				    value, 10, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'o':
				flags |= DP_F_UNSIGNED;
				အကယ်၍ (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned ကိန်းပြည့်);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long ကိန်းပြည့်);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_LLONG)
					value = (long)va_arg (args, unsigned LLONG);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				မဟုတ်ပါက
					value = (long)va_arg (args, unsigned ကိန်းပြည့်);
				အကယ်၍ (fmtint(buffer, &currlen, maxlen, value,
				    8, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'u':
				flags |= DP_F_UNSIGNED;
				အကယ်၍ (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned ကိန်းပြည့်);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long ကိန်းပြည့်);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_LLONG)
					value = (LLONG)va_arg (args, unsigned LLONG);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				မဟုတ်ပါက
					value = (long)va_arg (args, unsigned ကိန်းပြည့်);
				အကယ်၍ (fmtint(buffer, &currlen, maxlen, value,
				    10, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'X':
				flags |= DP_F_UP;
			pak_sa 'x':
				flags |= DP_F_UNSIGNED;
				အကယ်၍ (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned ကိန်းပြည့်);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long ကိန်းပြည့်);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_LLONG)
					value = (LLONG)va_arg (args, unsigned LLONG);
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				မဟုတ်ပါက အကယ်၍ (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				မဟုတ်ပါက
					value = (long)va_arg (args, unsigned ကိန်းပြည့်);
				အကယ်၍ (fmtint(buffer, &currlen, maxlen, value,
				    16, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'f':
				အကယ်၍ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				မဟုတ်ပါက
					fvalue = va_arg (args, dviguu_na);
				အကယ်၍ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'E':
				flags |= DP_F_UP;
			pak_sa 'e':
				အကယ်၍ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				မဟုတ်ပါက
					fvalue = va_arg (args, dviguu_na);
				အကယ်၍ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'G':
				flags |= DP_F_UP;
			pak_sa 'g':
				အကယ်၍ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				မဟုတ်ပါက
					fvalue = va_arg (args, dviguu_na);
				အကယ်၍ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, ကိန်းပြည့်));
				bha_nga;
			pak_sa 's':
				strvalue = va_arg (args, var_na *);
				အကယ်၍ (!strvalue) strvalue = "(NULL)";
				အကယ်၍ (max == -1) {
					max = strlen(strvalue);
				}
				အကယ်၍ (min > 0 && max >= 0 && min > max) max = min;
				အကယ်၍ (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					goto fail;
				bha_nga;
			pak_sa 'p':
				strvalue = va_arg (args, void *);
				အကယ်၍ (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					goto fail;
				bha_nga;
#အကယ်၍ we_dont_want_this_in_openssh
			pak_sa 'n':
				အကယ်၍ (cflags == DP_C_SHORT) {
					short ကိန်းပြည့် *num;
					num = va_arg (args, short ကိန်းပြည့် *);
					*num = currlen;
				} မဟုတ်ပါက အကယ်၍ (cflags == DP_C_LONG) {
					long ကိန်းပြည့် *num;
					num = va_arg (args, long ကိန်းပြည့် *);
					*num = (long ကိန်းပြည့်)currlen;
				} မဟုတ်ပါက အကယ်၍ (cflags == DP_C_LLONG) {
					LLONG *num;
					num = va_arg (args, LLONG *);
					*num = (LLONG)currlen;
				} မဟုတ်ပါက အကယ်၍ (cflags == DP_C_SIZE) {
					ssize_t *num;
					num = va_arg (args, ssize_t *);
					*num = (ssize_t)currlen;
				} မဟုတ်ပါက အကယ်၍ (cflags == DP_C_INTMAX) {
					intmax_t *num;
					num = va_arg (args, intmax_t *);
					*num = (intmax_t)currlen;
				} မဟုတ်ပါက {
					ကိန်းပြည့် *num;
					num = va_arg (args, ကိန်းပြည့် *);
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
	အကယ်၍ (maxlen != 0) {
		အကယ်၍ (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		မဟုတ်ပါက အကယ်၍ (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	ပြန်ပေး currlen < INT_MAX ? (ကိန်းပြည့်)currlen : -1;
 fail:
	va_end(args);
	ပြန်ပေး -1;
}

static ကိန်းပြည့်
fmtstr(var_na *buffer, size_t *currlen, size_t maxlen,
    var_na *value, ကိန်းပြည့် flags, ကိန်းပြည့် min, ကိန်းပြည့် max)
{
	ကိန်းပြည့် padlen, strln;     /* amount to pad */
	ကိန်းပြည့် cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, value);
#endif
	အကယ်၍ (value == 0) {
		value = "<NULL>";
	}

	အတွက် (strln = 0; strln < max && value[strln]; ++strln); /* strlen */
	padlen = min - strln;
	အကယ်၍ (padlen < 0)
		padlen = 0;
	အကယ်၍ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	နေစဉ် ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	နေစဉ် (*value && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *value);
		value++;
		++cnt;
	}
	နေစဉ် ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	ပြန်ပေး 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

static ကိန်းပြည့်
fmtint(var_na *buffer, size_t *currlen, size_t maxlen,
    intmax_t value, ကိန်းပြည့် base, ကိန်းပြည့် min, ကိန်းပြည့် max, ကိန်းပြည့် flags)
{
	ကိန်းပြည့် signvalue = 0;
	unsigned LLONG uvalue;
	var_na convert[20];
	ကိန်းပြည့် place = 0;
	ကိန်းပြည့် spadlen = 0; /* amount to space pad */
	ကိန်းပြည့် zpadlen = 0; /* amount to zero pad */
	ကိန်းပြည့် caps = 0;

	အကယ်၍ (max < 0)
		max = 0;

	uvalue = value;

	အကယ်၍(!(flags & DP_F_UNSIGNED)) {
		အကယ်၍( value < 0 ) {
			signvalue = '-';
			uvalue = -value;
		} မဟုတ်ပါက {
			အကယ်၍ (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			မဟုတ်ပါက အကယ်၍ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	အကယ်၍ (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	do {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} နေစဉ်(uvalue && (place < 20));
	အကယ်၍ (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	အကယ်၍ (zpadlen < 0) zpadlen = 0;
	အကယ်၍ (spadlen < 0) spadlen = 0;
	အကယ်၍ (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	အကယ်၍ (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	နေစဉ် (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	အကယ်၍ (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	အကယ်၍ (zpadlen > 0) {
		နေစဉ် (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	နေစဉ် (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	နေစဉ် (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	ပြန်ပေး 0;
}

static LDOUBLE abs_val(LDOUBLE value)
{
	LDOUBLE result = value;

	အကယ်၍ (value < 0)
		result = -value;

	ပြန်ပေး result;
}

static LDOUBLE POW10(ကိန်းပြည့် val)
{
	LDOUBLE result = 1;

	နေစဉ် (val) {
		result *= 10;
		val--;
	}

	ပြန်ပေး result;
}

static LLONG ROUND(LDOUBLE value)
{
	LLONG intpart;

	intpart = (LLONG)value;
	value = value - intpart;
	အကယ်၍ (value >= 0.5) intpart++;

	ပြန်ပေး intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
static dviguu_na my_modf(dviguu_na x0, dviguu_na *iptr)
{
	ကိန်းပြည့် i;
	long l;
	dviguu_na x = x0;
	dviguu_na f = 1.0;

	အတွက် (i=0;i<100;i++) {
		l = (long)x;
		အကယ်၍ (l <= (x+1) && l >= (x-1)) bha_nga;
		x *= 0.1;
		f *= 10.0;
	}

	အကယ်၍ (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		ပြန်ပေး 0;
	}

	အကယ်၍ (i != 0) {
		dviguu_na i2;
		dviguu_na ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		ပြန်ပေး ret;
	}

	(*iptr) = l;
	ပြန်ပေး x - (*iptr);
}


static ကိန်းပြည့်
fmtfp (var_na *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, ကိန်းပြည့် min, ကိန်းပြည့် max, ကိန်းပြည့် flags)
{
	ကိန်းပြည့် signvalue = 0;
	dviguu_na ufvalue;
	var_na iconvert[311];
	var_na fconvert[311];
	ကိန်းပြည့် iplace = 0;
	ကိန်းပြည့် fplace = 0;
	ကိန်းပြည့် padlen = 0; /* amount to pad */
	ကိန်းပြည့် zpadlen = 0;
#အကယ်၍ 0
	ကိန်းပြည့် caps = 0;
#endif
	ကိန်းပြည့် idx;
	dviguu_na intpart;
	dviguu_na fracpart;
	dviguu_na temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	အကယ်၍ (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	အကယ်၍ (fvalue < 0) {
		signvalue = '-';
	} မဟုတ်ပါက {
		အကယ်၍ (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} မဟုတ်ပါက {
			အကယ်၍ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#အကယ်၍ 0
	အကယ်၍ (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#အကယ်၍ 0
	 အကယ်၍ (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	အကယ်၍ (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	အကယ်၍ (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	do {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (ကိန်းပြည့်) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} နေစဉ် (intpart && (iplace < 311));
	အကယ်၍ (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	အကယ်၍ (fracpart)
	{
		do {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (ကိန်းပြည့်) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} နေစဉ်(fracpart && (fplace < 311));
		အကယ်၍ (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	အကယ်၍ (zpadlen < 0) zpadlen = 0;
	အကယ်၍ (padlen < 0)
		padlen = 0;
	အကယ်၍ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	အကယ်၍ ((flags & DP_F_ZERO) && (padlen > 0)) {
		အကယ်၍ (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		နေစဉ် (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	နေစဉ် (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	အကယ်၍ (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	နေစဉ် (iplace > 0) {
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
	အကယ်၍ (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		နေစဉ် (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		နေစဉ် (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	နေစဉ် (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	ပြန်ပေး 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#အကယ်၍ !defined(HAVE_VSNPRINTF)
ကိန်းပြည့်
vsnprintf (var_na *str, size_t count, const var_na *fmt, va_list args)
{
	ပြန်ပေး dopr(str, count, fmt, args);
}
#endif

#အကယ်၍ !defined(HAVE_SNPRINTF)
ကိန်းပြည့်
snprintf(var_na *str, size_t count, SNPRINTF_CONST var_na *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, count, fmt, ap);
	va_end(ap);
	ပြန်ပေး ret;
}
#endif
