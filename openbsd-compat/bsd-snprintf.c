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

#ຖ້າ defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#ຖ້າ !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long dviguu_na
#ບໍ່ດັ່ງນັ້ນ
# define LDOUBLE dviguu_na
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#ບໍ່ດັ່ງນັ້ນ
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
		ຖ້າ (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			ສົ່ງຄືນ -1; \
		} \
		ຖ້າ (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} ໃນຂະນະທີ່ (0)

static ຈຳນວນເຕັມ dopr(var_na *buffer, size_t maxlen, const var_na *format,
    va_list args_in);
static ຈຳນວນເຕັມ fmtstr(var_na *buffer, size_t *currlen, size_t maxlen,
    var_na *value, ຈຳນວນເຕັມ flags, ຈຳນວນເຕັມ min, ຈຳນວນເຕັມ max);
static ຈຳນວນເຕັມ fmtint(var_na *buffer, size_t *currlen, size_t maxlen,
    intmax_t value, ຈຳນວນເຕັມ base, ຈຳນວນເຕັມ min, ຈຳນວນເຕັມ max, ຈຳນວນເຕັມ flags);
static ຈຳນວນເຕັມ fmtfp(var_na *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, ຈຳນວນເຕັມ min, ຈຳນວນເຕັມ max, ຈຳນວນເຕັມ flags);

static ຈຳນວນເຕັມ
dopr(var_na *buffer, size_t maxlen, const var_na *format, va_list args_in)
{
	var_na ch;
	intmax_t value;
	LDOUBLE fvalue;
	var_na *strvalue;
	ຈຳນວນເຕັມ min;
	ຈຳນວນເຕັມ max;
	ຈຳນວນເຕັມ state;
	ຈຳນວນເຕັມ flags;
	ຈຳນວນເຕັມ cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	ໃນຂະນະທີ່ (state != DP_S_DONE) {
		ຖ້າ (ch == '\0')
			state = DP_S_DONE;

		switch(state) {
		pak_sa DP_S_DEFAULT:
			ຖ້າ (ch == '%')
				state = DP_S_FLAGS;
			ບໍ່ດັ່ງນັ້ນ
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
			ຖ້າ (isdigit((unsigned var_na)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} ບໍ່ດັ່ງນັ້ນ ຖ້າ (ch == '*') {
				min = va_arg (args, ຈຳນວນເຕັມ);
				ch = *format++;
				state = DP_S_DOT;
			} ບໍ່ດັ່ງນັ້ນ {
				state = DP_S_DOT;
			}
			bha_nga;
		pak_sa DP_S_DOT:
			ຖ້າ (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} ບໍ່ດັ່ງນັ້ນ {
				state = DP_S_MOD;
			}
			bha_nga;
		pak_sa DP_S_MAX:
			ຖ້າ (isdigit((unsigned var_na)ch)) {
				ຖ້າ (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} ບໍ່ດັ່ງນັ້ນ ຖ້າ (ch == '*') {
				max = va_arg (args, ຈຳນວນເຕັມ);
				ch = *format++;
				state = DP_S_MOD;
			} ບໍ່ດັ່ງນັ້ນ {
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
				ຖ້າ (ch == 'l') {	/* It's a long long */
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
				ຖ້າ (cflags == DP_C_SHORT)
					value = va_arg (args, ຈຳນວນເຕັມ);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_LONG)
					value = va_arg (args, long ຈຳນວນເຕັມ);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_LLONG)
					value = va_arg (args, LLONG);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_SIZE)
					value = va_arg (args, ssize_t);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_INTMAX)
					value = va_arg (args, intmax_t);
				ບໍ່ດັ່ງນັ້ນ
					value = va_arg (args, ຈຳນວນເຕັມ);
				ຖ້າ (fmtint(buffer, &currlen, maxlen,
				    value, 10, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'o':
				flags |= DP_F_UNSIGNED;
				ຖ້າ (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned ຈຳນວນເຕັມ);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long ຈຳນວນເຕັມ);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_LLONG)
					value = (long)va_arg (args, unsigned LLONG);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				ບໍ່ດັ່ງນັ້ນ
					value = (long)va_arg (args, unsigned ຈຳນວນເຕັມ);
				ຖ້າ (fmtint(buffer, &currlen, maxlen, value,
				    8, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'u':
				flags |= DP_F_UNSIGNED;
				ຖ້າ (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned ຈຳນວນເຕັມ);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long ຈຳນວນເຕັມ);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_LLONG)
					value = (LLONG)va_arg (args, unsigned LLONG);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				ບໍ່ດັ່ງນັ້ນ
					value = (long)va_arg (args, unsigned ຈຳນວນເຕັມ);
				ຖ້າ (fmtint(buffer, &currlen, maxlen, value,
				    10, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'X':
				flags |= DP_F_UP;
			pak_sa 'x':
				flags |= DP_F_UNSIGNED;
				ຖ້າ (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned ຈຳນວນເຕັມ);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long ຈຳນວນເຕັມ);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_LLONG)
					value = (LLONG)va_arg (args, unsigned LLONG);
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				ບໍ່ດັ່ງນັ້ນ
					value = (long)va_arg (args, unsigned ຈຳນວນເຕັມ);
				ຖ້າ (fmtint(buffer, &currlen, maxlen, value,
				    16, min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'f':
				ຖ້າ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				ບໍ່ດັ່ງນັ້ນ
					fvalue = va_arg (args, dviguu_na);
				ຖ້າ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'E':
				flags |= DP_F_UP;
			pak_sa 'e':
				ຖ້າ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				ບໍ່ດັ່ງນັ້ນ
					fvalue = va_arg (args, dviguu_na);
				ຖ້າ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'G':
				flags |= DP_F_UP;
			pak_sa 'g':
				ຖ້າ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				ບໍ່ດັ່ງນັ້ນ
					fvalue = va_arg (args, dviguu_na);
				ຖ້າ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				bha_nga;
			pak_sa 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, ຈຳນວນເຕັມ));
				bha_nga;
			pak_sa 's':
				strvalue = va_arg (args, var_na *);
				ຖ້າ (!strvalue) strvalue = "(NULL)";
				ຖ້າ (max == -1) {
					max = strlen(strvalue);
				}
				ຖ້າ (min > 0 && max >= 0 && min > max) max = min;
				ຖ້າ (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					goto fail;
				bha_nga;
			pak_sa 'p':
				strvalue = va_arg (args, void *);
				ຖ້າ (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					goto fail;
				bha_nga;
#ຖ້າ we_dont_want_this_in_openssh
			pak_sa 'n':
				ຖ້າ (cflags == DP_C_SHORT) {
					short ຈຳນວນເຕັມ *num;
					num = va_arg (args, short ຈຳນວນເຕັມ *);
					*num = currlen;
				} ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_LONG) {
					long ຈຳນວນເຕັມ *num;
					num = va_arg (args, long ຈຳນວນເຕັມ *);
					*num = (long ຈຳນວນເຕັມ)currlen;
				} ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_LLONG) {
					LLONG *num;
					num = va_arg (args, LLONG *);
					*num = (LLONG)currlen;
				} ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_SIZE) {
					ssize_t *num;
					num = va_arg (args, ssize_t *);
					*num = (ssize_t)currlen;
				} ບໍ່ດັ່ງນັ້ນ ຖ້າ (cflags == DP_C_INTMAX) {
					intmax_t *num;
					num = va_arg (args, intmax_t *);
					*num = (intmax_t)currlen;
				} ບໍ່ດັ່ງນັ້ນ {
					ຈຳນວນເຕັມ *num;
					num = va_arg (args, ຈຳນວນເຕັມ *);
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
	ຖ້າ (maxlen != 0) {
		ຖ້າ (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	ສົ່ງຄືນ currlen < INT_MAX ? (ຈຳນວນເຕັມ)currlen : -1;
 fail:
	va_end(args);
	ສົ່ງຄືນ -1;
}

static ຈຳນວນເຕັມ
fmtstr(var_na *buffer, size_t *currlen, size_t maxlen,
    var_na *value, ຈຳນວນເຕັມ flags, ຈຳນວນເຕັມ min, ຈຳນວນເຕັມ max)
{
	ຈຳນວນເຕັມ padlen, strln;     /* amount to pad */
	ຈຳນວນເຕັມ cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, value);
#endif
	ຖ້າ (value == 0) {
		value = "<NULL>";
	}

	ສຳລັບ (strln = 0; strln < max && value[strln]; ++strln); /* strlen */
	padlen = min - strln;
	ຖ້າ (padlen < 0)
		padlen = 0;
	ຖ້າ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	ໃນຂະນະທີ່ ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	ໃນຂະນະທີ່ (*value && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *value);
		value++;
		++cnt;
	}
	ໃນຂະນະທີ່ ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	ສົ່ງຄືນ 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

static ຈຳນວນເຕັມ
fmtint(var_na *buffer, size_t *currlen, size_t maxlen,
    intmax_t value, ຈຳນວນເຕັມ base, ຈຳນວນເຕັມ min, ຈຳນວນເຕັມ max, ຈຳນວນເຕັມ flags)
{
	ຈຳນວນເຕັມ signvalue = 0;
	unsigned LLONG uvalue;
	var_na convert[20];
	ຈຳນວນເຕັມ place = 0;
	ຈຳນວນເຕັມ spadlen = 0; /* amount to space pad */
	ຈຳນວນເຕັມ zpadlen = 0; /* amount to zero pad */
	ຈຳນວນເຕັມ caps = 0;

	ຖ້າ (max < 0)
		max = 0;

	uvalue = value;

	ຖ້າ(!(flags & DP_F_UNSIGNED)) {
		ຖ້າ( value < 0 ) {
			signvalue = '-';
			uvalue = -value;
		} ບໍ່ດັ່ງນັ້ນ {
			ຖ້າ (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			ບໍ່ດັ່ງນັ້ນ ຖ້າ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	ຖ້າ (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	do {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} ໃນຂະນະທີ່(uvalue && (place < 20));
	ຖ້າ (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	ຖ້າ (zpadlen < 0) zpadlen = 0;
	ຖ້າ (spadlen < 0) spadlen = 0;
	ຖ້າ (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	ຖ້າ (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	ໃນຂະນະທີ່ (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	ຖ້າ (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	ຖ້າ (zpadlen > 0) {
		ໃນຂະນະທີ່ (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	ໃນຂະນະທີ່ (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	ໃນຂະນະທີ່ (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	ສົ່ງຄືນ 0;
}

static LDOUBLE abs_val(LDOUBLE value)
{
	LDOUBLE result = value;

	ຖ້າ (value < 0)
		result = -value;

	ສົ່ງຄືນ result;
}

static LDOUBLE POW10(ຈຳນວນເຕັມ val)
{
	LDOUBLE result = 1;

	ໃນຂະນະທີ່ (val) {
		result *= 10;
		val--;
	}

	ສົ່ງຄືນ result;
}

static LLONG ROUND(LDOUBLE value)
{
	LLONG intpart;

	intpart = (LLONG)value;
	value = value - intpart;
	ຖ້າ (value >= 0.5) intpart++;

	ສົ່ງຄືນ intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
static dviguu_na my_modf(dviguu_na x0, dviguu_na *iptr)
{
	ຈຳນວນເຕັມ i;
	long l;
	dviguu_na x = x0;
	dviguu_na f = 1.0;

	ສຳລັບ (i=0;i<100;i++) {
		l = (long)x;
		ຖ້າ (l <= (x+1) && l >= (x-1)) bha_nga;
		x *= 0.1;
		f *= 10.0;
	}

	ຖ້າ (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		ສົ່ງຄືນ 0;
	}

	ຖ້າ (i != 0) {
		dviguu_na i2;
		dviguu_na ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		ສົ່ງຄືນ ret;
	}

	(*iptr) = l;
	ສົ່ງຄືນ x - (*iptr);
}


static ຈຳນວນເຕັມ
fmtfp (var_na *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, ຈຳນວນເຕັມ min, ຈຳນວນເຕັມ max, ຈຳນວນເຕັມ flags)
{
	ຈຳນວນເຕັມ signvalue = 0;
	dviguu_na ufvalue;
	var_na iconvert[311];
	var_na fconvert[311];
	ຈຳນວນເຕັມ iplace = 0;
	ຈຳນວນເຕັມ fplace = 0;
	ຈຳນວນເຕັມ padlen = 0; /* amount to pad */
	ຈຳນວນເຕັມ zpadlen = 0;
#ຖ້າ 0
	ຈຳນວນເຕັມ caps = 0;
#endif
	ຈຳນວນເຕັມ idx;
	dviguu_na intpart;
	dviguu_na fracpart;
	dviguu_na temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	ຖ້າ (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	ຖ້າ (fvalue < 0) {
		signvalue = '-';
	} ບໍ່ດັ່ງນັ້ນ {
		ຖ້າ (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} ບໍ່ດັ່ງນັ້ນ {
			ຖ້າ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#ຖ້າ 0
	ຖ້າ (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#ຖ້າ 0
	 ຖ້າ (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	ຖ້າ (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	ຖ້າ (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	do {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (ຈຳນວນເຕັມ) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} ໃນຂະນະທີ່ (intpart && (iplace < 311));
	ຖ້າ (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	ຖ້າ (fracpart)
	{
		do {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (ຈຳນວນເຕັມ) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} ໃນຂະນະທີ່(fracpart && (fplace < 311));
		ຖ້າ (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	ຖ້າ (zpadlen < 0) zpadlen = 0;
	ຖ້າ (padlen < 0)
		padlen = 0;
	ຖ້າ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	ຖ້າ ((flags & DP_F_ZERO) && (padlen > 0)) {
		ຖ້າ (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		ໃນຂະນະທີ່ (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	ໃນຂະນະທີ່ (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	ຖ້າ (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	ໃນຂະນະທີ່ (iplace > 0) {
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
	ຖ້າ (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		ໃນຂະນະທີ່ (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		ໃນຂະນະທີ່ (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	ໃນຂະນະທີ່ (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	ສົ່ງຄືນ 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#ຖ້າ !defined(HAVE_VSNPRINTF)
ຈຳນວນເຕັມ
vsnprintf (var_na *str, size_t count, const var_na *fmt, va_list args)
{
	ສົ່ງຄືນ dopr(str, count, fmt, args);
}
#endif

#ຖ້າ !defined(HAVE_SNPRINTF)
ຈຳນວນເຕັມ
snprintf(var_na *str, size_t count, SNPRINTF_CONST var_na *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, count, fmt, ap);
	va_end(ap);
	ສົ່ງຄືນ ret;
}
#endif
