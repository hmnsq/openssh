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

#ضمن "includes.h"

#إذا defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#جيڪڏهن_پورو

#إذا !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#ضمن <ctype.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <limits.h>
#ضمن <errno.h>

#جيڪڏهن_وصف_ٿيل HAVE_LONG_DOUBLE
# define LDOUBLE ڊگهو مزدوج
#وإلا
# define LDOUBLE مزدوج
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل HAVE_LONG_LONG
# define LLONG ڊگهو ڊگهو
#وإلا
# define LLONG ڊگهو
#جيڪڏهن_پورو

/*
 * dopr(): poor man's version of doprintf
 */

/* format read states */
#وصف_ڪريو DP_S_DEFAULT 0
#وصف_ڪريو DP_S_FLAGS   1
#وصف_ڪريو DP_S_MIN     2
#وصف_ڪريو DP_S_DOT     3
#وصف_ڪريو DP_S_MAX     4
#وصف_ڪريو DP_S_MOD     5
#وصف_ڪريو DP_S_CONV    6
#وصف_ڪريو DP_S_پورو    7

/* format flags - Bits */
#وصف_ڪريو DP_F_MINUS	(1 << 0)
#وصف_ڪريو DP_F_PLUS	(1 << 1)
#وصف_ڪريو DP_F_SPACE	(1 << 2)
#وصف_ڪريو DP_F_انگ	(1 << 3)
#وصف_ڪريو DP_F_ZERO	(1 << 4)
#وصف_ڪريو DP_F_مٿي		(1 << 5)
#وصف_ڪريو DP_F_UNSIGNED	(1 << 6)

/* Conversion Flags */
#وصف_ڪريو DP_C_SHORT   1
#وصف_ڪريو DP_C_LONG    2
#وصف_ڪريو DP_C_LDOUBLE 3
#وصف_ڪريو DP_C_LLONG   4
#وصف_ڪريو DP_C_سائيز    5
#وصف_ڪريو DP_C_INTMAX  6

#وصف_ڪريو char_منزل_int(p) ((p)- '0')
#جيڪڏهن_وصف_نه_ٿيل MAX
# define MAX(p,q) (((p) >= (q)) ? (p) : (q))
#جيڪڏهن_پورو

#وصف_ڪريو DOPR_OUTCH(buf, pos, buflen, thechar) \
	افعل { \
		إذا (pos + 1 >= وڌ_کان_وڌ_عدد) { \
			errno = ERANGE; \
			أرجع -1; \
		} \
		إذا (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} طالما (0)

ساكن صحيح dopr(حرف *بفر, سائيز_t maxlen, ثابت حرف *format,
    va_list دليلون_اندريون);
ساكن صحيح fmtstr(حرف *بفر, سائيز_t *currlen, سائيز_t maxlen,
    حرف *قدر, صحيح flags, صحيح min, صحيح max);
ساكن صحيح fmtint(حرف *بفر, سائيز_t *currlen, سائيز_t maxlen,
    intmax_t قدر, صحيح بنياد, صحيح min, صحيح max, صحيح flags);
ساكن صحيح fmtfp(حرف *بفر, سائيز_t *currlen, سائيز_t maxlen,
    LDOUBLE fvalue, صحيح min, صحيح max, صحيح flags);

ساكن صحيح
dopr(حرف *بفر, سائيز_t maxlen, ثابت حرف *format, va_list دليلون_اندريون)
{
	حرف ch;
	intmax_t قدر;
	LDOUBLE fvalue;
	حرف *strvalue;
	صحيح min;
	صحيح max;
	صحيح state;
	صحيح flags;
	صحيح cflags;
	سائيز_t currlen;
	va_list دليلون;

	VA_COPY(دليلون, دليلون_اندريون);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	طالما (state != DP_S_پورو) {
		إذا (ch == '\0')
			state = DP_S_پورو;

		بدل(state) {
		حالة DP_S_DEFAULT:
			إذا (ch == '%')
				state = DP_S_FLAGS;
			وإلا
				DOPR_OUTCH(بفر, currlen, maxlen, ch);
			ch = *format++;
			اكسر;
		حالة DP_S_FLAGS:
			بدل (ch) {
			حالة '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				اكسر;
			حالة '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				اكسر;
			حالة ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				اكسر;
			حالة '#':
				flags |= DP_F_انگ;
				ch = *format++;
				اكسر;
			حالة '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				اكسر;
			افتراضي:
				state = DP_S_MIN;
				اكسر;
			}
			اكسر;
		حالة DP_S_MIN:
			إذا (انگ_آهي((بنانشان حرف)ch)) {
				min = 10*min + char_منزل_int (ch);
				ch = *format++;
			} وإلا إذا (ch == '*') {
				min = va_arg (دليلون, صحيح);
				ch = *format++;
				state = DP_S_DOT;
			} وإلا {
				state = DP_S_DOT;
			}
			اكسر;
		حالة DP_S_DOT:
			إذا (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} وإلا {
				state = DP_S_MOD;
			}
			اكسر;
		حالة DP_S_MAX:
			إذا (انگ_آهي((بنانشان حرف)ch)) {
				إذا (max < 0)
					max = 0;
				max = 10*max + char_منزل_int (ch);
				ch = *format++;
			} وإلا إذا (ch == '*') {
				max = va_arg (دليلون, صحيح);
				ch = *format++;
				state = DP_S_MOD;
			} وإلا {
				state = DP_S_MOD;
			}
			اكسر;
		حالة DP_S_MOD:
			بدل (ch) {
			حالة 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				اكسر;
			حالة 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				اكسر;
			حالة 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				إذا (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				اكسر;
			حالة 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				اكسر;
			حالة 'z':
				cflags = DP_C_سائيز;
				ch = *format++;
				اكسر;
			افتراضي:
				اكسر;
			}
			state = DP_S_CONV;
			اكسر;
		حالة DP_S_CONV:
			بدل (ch) {
			حالة 'd':
			حالة 'i':
				إذا (cflags == DP_C_SHORT)
					قدر = va_arg (دليلون, صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					قدر = va_arg (دليلون, ڊگهو صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					قدر = va_arg (دليلون, LLONG);
				وإلا إذا (cflags == DP_C_سائيز)
					قدر = va_arg (دليلون, ssize_t);
				وإلا إذا (cflags == DP_C_INTMAX)
					قدر = va_arg (دليلون, intmax_t);
				وإلا
					قدر = va_arg (دليلون, صحيح);
				إذا (fmtint(بفر, &currlen, maxlen,
				    قدر, 10, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'o':
				flags |= DP_F_UNSIGNED;
				إذا (cflags == DP_C_SHORT)
					قدر = va_arg (دليلون, بنانشان صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					قدر = (ڊگهو)va_arg (دليلون, بنانشان ڊگهو صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					قدر = (ڊگهو)va_arg (دليلون, بنانشان LLONG);
				وإلا إذا (cflags == DP_C_سائيز)
					قدر = va_arg (دليلون, سائيز_t);
#جيڪڏهن_وصف_ٿيل notyet
				وإلا إذا (cflags == DP_C_INTMAX)
					قدر = va_arg (دليلون, uintmax_t);
#جيڪڏهن_پورو
				وإلا
					قدر = (ڊگهو)va_arg (دليلون, بنانشان صحيح);
				إذا (fmtint(بفر, &currlen, maxlen, قدر,
				    8, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'u':
				flags |= DP_F_UNSIGNED;
				إذا (cflags == DP_C_SHORT)
					قدر = va_arg (دليلون, بنانشان صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					قدر = (ڊگهو)va_arg (دليلون, بنانشان ڊگهو صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					قدر = (LLONG)va_arg (دليلون, بنانشان LLONG);
				وإلا إذا (cflags == DP_C_سائيز)
					قدر = va_arg (دليلون, سائيز_t);
#جيڪڏهن_وصف_ٿيل notyet
				وإلا إذا (cflags == DP_C_INTMAX)
					قدر = va_arg (دليلون, uintmax_t);
#جيڪڏهن_پورو
				وإلا
					قدر = (ڊگهو)va_arg (دليلون, بنانشان صحيح);
				إذا (fmtint(بفر, &currlen, maxlen, قدر,
				    10, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'X':
				flags |= DP_F_مٿي;
			حالة 'x':
				flags |= DP_F_UNSIGNED;
				إذا (cflags == DP_C_SHORT)
					قدر = va_arg (دليلون, بنانشان صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					قدر = (ڊگهو)va_arg (دليلون, بنانشان ڊگهو صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					قدر = (LLONG)va_arg (دليلون, بنانشان LLONG);
				وإلا إذا (cflags == DP_C_سائيز)
					قدر = va_arg (دليلون, سائيز_t);
#جيڪڏهن_وصف_ٿيل notyet
				وإلا إذا (cflags == DP_C_INTMAX)
					قدر = va_arg (دليلون, uintmax_t);
#جيڪڏهن_پورو
				وإلا
					قدر = (ڊگهو)va_arg (دليلون, بنانشان صحيح);
				إذا (fmtint(بفر, &currlen, maxlen, قدر,
				    16, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'f':
				إذا (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (دليلون, LDOUBLE);
				وإلا
					fvalue = va_arg (دليلون, مزدوج);
				إذا (fmtfp(بفر, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'E':
				flags |= DP_F_مٿي;
			حالة 'e':
				إذا (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (دليلون, LDOUBLE);
				وإلا
					fvalue = va_arg (دليلون, مزدوج);
				إذا (fmtfp(بفر, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'G':
				flags |= DP_F_مٿي;
			حالة 'g':
				إذا (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (دليلون, LDOUBLE);
				وإلا
					fvalue = va_arg (دليلون, مزدوج);
				إذا (fmtfp(بفر, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'c':
				DOPR_OUTCH(بفر, currlen, maxlen,
				    va_arg (دليلون, صحيح));
				اكسر;
			حالة 's':
				strvalue = va_arg (دليلون, حرف *);
				إذا (!strvalue) strvalue = "(NULL)";
				إذا (max == -1) {
					max = لڙي_ڊيگهه(strvalue);
				}
				إذا (min > 0 && max >= 0 && min > max) max = min;
				إذا (fmtstr(بفر, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					اذهب fail;
				اكسر;
			حالة 'p':
				strvalue = va_arg (دليلون, فراغ *);
				إذا (fmtint(بفر, &currlen, maxlen,
				    (ڊگهو) strvalue, 16, min, max, flags) == -1)
					اذهب fail;
				اكسر;
#إذا we_dont_want_this_اندريون_openssh
			حالة 'n':
				إذا (cflags == DP_C_SHORT) {
					ننڍو صحيح *انگ;
					انگ = va_arg (دليلون, ننڍو صحيح *);
					*انگ = currlen;
				} وإلا إذا (cflags == DP_C_LONG) {
					ڊگهو صحيح *انگ;
					انگ = va_arg (دليلون, ڊگهو صحيح *);
					*انگ = (ڊگهو صحيح)currlen;
				} وإلا إذا (cflags == DP_C_LLONG) {
					LLONG *انگ;
					انگ = va_arg (دليلون, LLONG *);
					*انگ = (LLONG)currlen;
				} وإلا إذا (cflags == DP_C_سائيز) {
					ssize_t *انگ;
					انگ = va_arg (دليلون, ssize_t *);
					*انگ = (ssize_t)currlen;
				} وإلا إذا (cflags == DP_C_INTMAX) {
					intmax_t *انگ;
					انگ = va_arg (دليلون, intmax_t *);
					*انگ = (intmax_t)currlen;
				} وإلا {
					صحيح *انگ;
					انگ = va_arg (دليلون, صحيح *);
					*انگ = currlen;
				}
				اكسر;
#جيڪڏهن_پورو
			حالة '%':
				DOPR_OUTCH(بفر, currlen, maxlen, ch);
				اكسر;
			افتراضي:
				/* Unknown, skip */
				اكسر;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			اكسر;
		حالة DP_S_پورو:
			اكسر;
		افتراضي:
			/* hmm? */
			اكسر; /* some picky compilers need this */
		}
	}
	إذا (maxlen != 0) {
		إذا (currlen < maxlen - 1)
			بفر[currlen] = '\0';
		وإلا إذا (maxlen > 0)
			بفر[maxlen - 1] = '\0';
	}
	va_end(دليلون);
	أرجع currlen < وڌ_کان_وڌ_عدد ? (صحيح)currlen : -1;
 fail:
	va_end(دليلون);
	أرجع -1;
}

ساكن صحيح
fmtstr(حرف *بفر, سائيز_t *currlen, سائيز_t maxlen,
    حرف *قدر, صحيح flags, صحيح min, صحيح max)
{
	صحيح padlen, strln;     /* amount to pad */
	صحيح cnt = 0;

#جيڪڏهن_وصف_ٿيل DEBUG_SNPRINTF
	لکو("fmtstr min=%d max=%d s=[%s]\n", min, max, قدر);
#جيڪڏهن_پورو
	إذا (قدر == 0) {
		قدر = "<NULL>";
	}

	لكل (strln = 0; strln < max && قدر[strln]; ++strln); /* strlen */
	padlen = min - strln;
	إذا (padlen < 0)
		padlen = 0;
	إذا (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	طالما ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	طالما (*قدر && (cnt < max)) {
		DOPR_OUTCH(بفر, *currlen, maxlen, *قدر);
		قدر++;
		++cnt;
	}
	طالما ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	أرجع 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

ساكن صحيح
fmtint(حرف *بفر, سائيز_t *currlen, سائيز_t maxlen,
    intmax_t قدر, صحيح بنياد, صحيح min, صحيح max, صحيح flags)
{
	صحيح signvalue = 0;
	بنانشان LLONG uvalue;
	حرف convert[20];
	صحيح رکو = 0;
	صحيح spadlen = 0; /* amount to space pad */
	صحيح zpadlen = 0; /* amount to zero pad */
	صحيح caps = 0;

	إذا (max < 0)
		max = 0;

	uvalue = قدر;

	إذا(!(flags & DP_F_UNSIGNED)) {
		إذا( قدر < 0 ) {
			signvalue = '-';
			uvalue = -قدر;
		} وإلا {
			إذا (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			وإلا إذا (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	إذا (flags & DP_F_مٿي) caps = 1; /* Should characters be upper case? */

	افعل {
		convert[رکو++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (بنانشان)بنياد  ];
		uvalue = (uvalue / (بنانشان)بنياد );
	} طالما(uvalue && (رکو < 20));
	إذا (رکو == 20) رکو--;
	convert[رکو] = 0;

	zpadlen = max - رکو;
	spadlen = min - MAX (max, رکو) - (signvalue ? 1 : 0);
	إذا (zpadlen < 0) zpadlen = 0;
	إذا (spadlen < 0) spadlen = 0;
	إذا (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	إذا (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#جيڪڏهن_وصف_ٿيل DEBUG_SNPRINTF
	لکو("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, رکو);
#جيڪڏهن_پورو

	/* Spaces */
	طالما (spadlen > 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	إذا (signvalue)
		DOPR_OUTCH(بفر, *currlen, maxlen, signvalue);

	/* Zeros */
	إذا (zpadlen > 0) {
		طالما (zpadlen > 0) {
			DOPR_OUTCH(بفر, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	طالما (رکو > 0) {
		--رکو;
		DOPR_OUTCH(بفر, *currlen, maxlen, convert[رکو]);
	}

	/* Left Justified spaces */
	طالما (spadlen < 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		++spadlen;
	}
	أرجع 0;
}

ساكن LDOUBLE abs_val(LDOUBLE قدر)
{
	LDOUBLE نتيجو = قدر;

	إذا (قدر < 0)
		نتيجو = -قدر;

	أرجع نتيجو;
}

ساكن LDOUBLE POW10(صحيح val)
{
	LDOUBLE نتيجو = 1;

	طالما (val) {
		نتيجو *= 10;
		val--;
	}

	أرجع نتيجو;
}

ساكن LLONG ڦيرو_2(LDOUBLE قدر)
{
	LLONG intpart;

	intpart = (LLONG)قدر;
	قدر = قدر - intpart;
	إذا (قدر >= 0.5) intpart++;

	أرجع intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
ساكن مزدوج my_modf(مزدوج x0, مزدوج *iptr)
{
	صحيح i;
	ڊگهو l;
	مزدوج x = x0;
	مزدوج f = 1.0;

	لكل (i=0;i<100;i++) {
		l = (ڊگهو)x;
		إذا (l <= (x+1) && l >= (x-1)) اكسر;
		x *= 0.1;
		f *= 10.0;
	}

	إذا (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		أرجع 0;
	}

	إذا (i != 0) {
		مزدوج i2;
		مزدوج ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		أرجع ret;
	}

	(*iptr) = l;
	أرجع x - (*iptr);
}


ساكن صحيح
fmtfp (حرف *بفر, سائيز_t *currlen, سائيز_t maxlen,
    LDOUBLE fvalue, صحيح min, صحيح max, صحيح flags)
{
	صحيح signvalue = 0;
	مزدوج ufvalue;
	حرف iconvert[311];
	حرف fconvert[311];
	صحيح iplace = 0;
	صحيح fplace = 0;
	صحيح padlen = 0; /* amount to pad */
	صحيح zpadlen = 0;
#إذا 0
	صحيح caps = 0;
#جيڪڏهن_پورو
	صحيح idx;
	مزدوج intpart;
	مزدوج fracpart;
	مزدوج عارضي;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	إذا (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	إذا (fvalue < 0) {
		signvalue = '-';
	} وإلا {
		إذا (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} وإلا {
			إذا (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#إذا 0
	إذا (flags & DP_F_مٿي) caps = 1; /* Should characters be upper case? */
#جيڪڏهن_پورو

#إذا 0
	 إذا (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#جيڪڏهن_پورو

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	إذا (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	عارضي = ufvalue;
	my_modf(عارضي, &intpart);

	fracpart = ڦيرو_2((POW10(max)) * (ufvalue - intpart));

	إذا (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	افعل {
		عارضي = intpart*0.1;
		my_modf(عارضي, &intpart);
		idx = (صحيح) ((عارضي -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} طالما (intpart && (iplace < 311));
	إذا (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	إذا (fracpart)
	{
		افعل {
			عارضي = fracpart*0.1;
			my_modf(عارضي, &fracpart);
			idx = (صحيح) ((عارضي -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} طالما(fracpart && (fplace < 311));
		إذا (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	إذا (zpadlen < 0) zpadlen = 0;
	إذا (padlen < 0)
		padlen = 0;
	إذا (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	إذا ((flags & DP_F_ZERO) && (padlen > 0)) {
		إذا (signvalue) {
			DOPR_OUTCH(بفر, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		طالما (padlen > 0) {
			DOPR_OUTCH(بفر, *currlen, maxlen, '0');
			--padlen;
		}
	}
	طالما (padlen > 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		--padlen;
	}
	إذا (signvalue)
		DOPR_OUTCH(بفر, *currlen, maxlen, signvalue);

	طالما (iplace > 0) {
		--iplace;
		DOPR_OUTCH(بفر, *currlen, maxlen, iconvert[iplace]);
	}

#جيڪڏهن_وصف_ٿيل DEBUG_SNPRINTF
	لکو("fmtfp: fplace=%d zpadlen=%d\n", fplace, zpadlen);
#جيڪڏهن_پورو

	/*
	 * Decimal point.  This should probably use locale to find the correct
	 * char to print out.
	 */
	إذا (max > 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, '.');

		طالما (zpadlen > 0) {
			DOPR_OUTCH(بفر, *currlen, maxlen, '0');
			--zpadlen;
		}

		طالما (fplace > 0) {
			--fplace;
			DOPR_OUTCH(بفر, *currlen, maxlen, fconvert[fplace]);
		}
	}

	طالما (padlen < 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		++padlen;
	}
	أرجع 0;
}
#جيڪڏهن_پورو /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#إذا !defined(HAVE_VSNPRINTF)
صحيح
vsnprintf (حرف *str, سائيز_t ڳڻپ, ثابت حرف *fmt, va_list دليلون)
{
	أرجع dopr(str, ڳڻپ, fmt, دليلون);
}
#جيڪڏهن_پورو

#إذا !defined(HAVE_SNPRINTF)
صحيح
snprintf(حرف *str, سائيز_t ڳڻپ, SNPRINTF_CONST حرف *fmt, ...)
{
	سائيز_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, ڳڻپ, fmt, ap);
	va_end(ap);
	أرجع ret;
}
#جيڪڏهن_پورو
