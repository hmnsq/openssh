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

#شامل "includes.h"

#اگر defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#اگر_ختم

#اگر !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#شامل <ctype.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <limits.h>
#شامل <errno.h>

#اگر_تعریف_شدہ HAVE_LONG_DOUBLE
# define LDOUBLE طویل دوہرا
#ورنہ
# define LDOUBLE دوہرا
#اگر_ختم

#اگر_تعریف_شدہ HAVE_LONG_LONG
# define LLONG طویل طویل
#ورنہ
# define LLONG طویل
#اگر_ختم

/*
 * dopr(): poor man's version of doprintf
 */

/* format read states */
#تعریف_کرو DP_S_DEFAULT 0
#تعریف_کرو DP_S_FLAGS   1
#تعریف_کرو DP_S_MIN     2
#تعریف_کرو DP_S_DOT     3
#تعریف_کرو DP_S_MAX     4
#تعریف_کرو DP_S_MOD     5
#تعریف_کرو DP_S_CONV    6
#تعریف_کرو DP_S_مکمل    7

/* format flags - Bits */
#تعریف_کرو DP_F_MINUS	(1 << 0)
#تعریف_کرو DP_F_PLUS	(1 << 1)
#تعریف_کرو DP_F_SPACE	(1 << 2)
#تعریف_کرو DP_F_عدد	(1 << 3)
#تعریف_کرو DP_F_ZERO	(1 << 4)
#تعریف_کرو DP_F_اوپر		(1 << 5)
#تعریف_کرو DP_F_UNSIGNED	(1 << 6)

/* Conversion Flags */
#تعریف_کرو DP_C_SHORT   1
#تعریف_کرو DP_C_LONG    2
#تعریف_کرو DP_C_LDOUBLE 3
#تعریف_کرو DP_C_LLONG   4
#تعریف_کرو DP_C_سائز    5
#تعریف_کرو DP_C_INTMAX  6

#تعریف_کرو char_مقصد_int(p) ((p)- '0')
#اگر_غیر_تعریف_شدہ MAX
# define MAX(p,q) (((p) >= (q)) ? (p) : (q))
#اگر_ختم

#تعریف_کرو DOPR_OUTCH(buf, pos, buflen, thechar) \
	کرو { \
		اگر (pos + 1 >= زیادہ_سے_زیادہ_عدد) { \
			errno = ERANGE; \
			واپس -1; \
		} \
		اگر (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} جب (0)

ساکن صحیح dopr(حرف *بفر, سائز_t maxlen, ثابت حرف *format,
    va_list دلائل_اندر);
ساکن صحیح fmtstr(حرف *بفر, سائز_t *currlen, سائز_t maxlen,
    حرف *قدر, صحیح flags, صحیح min, صحیح max);
ساکن صحیح fmtint(حرف *بفر, سائز_t *currlen, سائز_t maxlen,
    intmax_t قدر, صحیح بنیاد, صحیح min, صحیح max, صحیح flags);
ساکن صحیح fmtfp(حرف *بفر, سائز_t *currlen, سائز_t maxlen,
    LDOUBLE fvalue, صحیح min, صحیح max, صحیح flags);

ساکن صحیح
dopr(حرف *بفر, سائز_t maxlen, ثابت حرف *format, va_list دلائل_اندر)
{
	حرف ch;
	intmax_t قدر;
	LDOUBLE fvalue;
	حرف *strvalue;
	صحیح min;
	صحیح max;
	صحیح state;
	صحیح flags;
	صحیح cflags;
	سائز_t currlen;
	va_list دلائل;

	VA_COPY(دلائل, دلائل_اندر);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	جب (state != DP_S_مکمل) {
		اگر (ch == '\0')
			state = DP_S_مکمل;

		انتخاب(state) {
		حالت DP_S_DEFAULT:
			اگر (ch == '%')
				state = DP_S_FLAGS;
			ورنہ
				DOPR_OUTCH(بفر, currlen, maxlen, ch);
			ch = *format++;
			توڑو;
		حالت DP_S_FLAGS:
			انتخاب (ch) {
			حالت '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				توڑو;
			حالت '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				توڑو;
			حالت ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				توڑو;
			حالت '#':
				flags |= DP_F_عدد;
				ch = *format++;
				توڑو;
			حالت '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				توڑو;
			طےشدہ:
				state = DP_S_MIN;
				توڑو;
			}
			توڑو;
		حالت DP_S_MIN:
			اگر (ہندسہ_ہے((غیرعلامتی حرف)ch)) {
				min = 10*min + char_مقصد_int (ch);
				ch = *format++;
			} ورنہ اگر (ch == '*') {
				min = va_arg (دلائل, صحیح);
				ch = *format++;
				state = DP_S_DOT;
			} ورنہ {
				state = DP_S_DOT;
			}
			توڑو;
		حالت DP_S_DOT:
			اگر (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} ورنہ {
				state = DP_S_MOD;
			}
			توڑو;
		حالت DP_S_MAX:
			اگر (ہندسہ_ہے((غیرعلامتی حرف)ch)) {
				اگر (max < 0)
					max = 0;
				max = 10*max + char_مقصد_int (ch);
				ch = *format++;
			} ورنہ اگر (ch == '*') {
				max = va_arg (دلائل, صحیح);
				ch = *format++;
				state = DP_S_MOD;
			} ورنہ {
				state = DP_S_MOD;
			}
			توڑو;
		حالت DP_S_MOD:
			انتخاب (ch) {
			حالت 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				توڑو;
			حالت 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				توڑو;
			حالت 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				اگر (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				توڑو;
			حالت 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				توڑو;
			حالت 'z':
				cflags = DP_C_سائز;
				ch = *format++;
				توڑو;
			طےشدہ:
				توڑو;
			}
			state = DP_S_CONV;
			توڑو;
		حالت DP_S_CONV:
			انتخاب (ch) {
			حالت 'd':
			حالت 'i':
				اگر (cflags == DP_C_SHORT)
					قدر = va_arg (دلائل, صحیح);
				ورنہ اگر (cflags == DP_C_LONG)
					قدر = va_arg (دلائل, طویل صحیح);
				ورنہ اگر (cflags == DP_C_LLONG)
					قدر = va_arg (دلائل, LLONG);
				ورنہ اگر (cflags == DP_C_سائز)
					قدر = va_arg (دلائل, ssize_t);
				ورنہ اگر (cflags == DP_C_INTMAX)
					قدر = va_arg (دلائل, intmax_t);
				ورنہ
					قدر = va_arg (دلائل, صحیح);
				اگر (fmtint(بفر, &currlen, maxlen,
				    قدر, 10, min, max, flags) == -1)
					جاؤ fail;
				توڑو;
			حالت 'o':
				flags |= DP_F_UNSIGNED;
				اگر (cflags == DP_C_SHORT)
					قدر = va_arg (دلائل, غیرعلامتی صحیح);
				ورنہ اگر (cflags == DP_C_LONG)
					قدر = (طویل)va_arg (دلائل, غیرعلامتی طویل صحیح);
				ورنہ اگر (cflags == DP_C_LLONG)
					قدر = (طویل)va_arg (دلائل, غیرعلامتی LLONG);
				ورنہ اگر (cflags == DP_C_سائز)
					قدر = va_arg (دلائل, سائز_t);
#اگر_تعریف_شدہ notyet
				ورنہ اگر (cflags == DP_C_INTMAX)
					قدر = va_arg (دلائل, uintmax_t);
#اگر_ختم
				ورنہ
					قدر = (طویل)va_arg (دلائل, غیرعلامتی صحیح);
				اگر (fmtint(بفر, &currlen, maxlen, قدر,
				    8, min, max, flags) == -1)
					جاؤ fail;
				توڑو;
			حالت 'u':
				flags |= DP_F_UNSIGNED;
				اگر (cflags == DP_C_SHORT)
					قدر = va_arg (دلائل, غیرعلامتی صحیح);
				ورنہ اگر (cflags == DP_C_LONG)
					قدر = (طویل)va_arg (دلائل, غیرعلامتی طویل صحیح);
				ورنہ اگر (cflags == DP_C_LLONG)
					قدر = (LLONG)va_arg (دلائل, غیرعلامتی LLONG);
				ورنہ اگر (cflags == DP_C_سائز)
					قدر = va_arg (دلائل, سائز_t);
#اگر_تعریف_شدہ notyet
				ورنہ اگر (cflags == DP_C_INTMAX)
					قدر = va_arg (دلائل, uintmax_t);
#اگر_ختم
				ورنہ
					قدر = (طویل)va_arg (دلائل, غیرعلامتی صحیح);
				اگر (fmtint(بفر, &currlen, maxlen, قدر,
				    10, min, max, flags) == -1)
					جاؤ fail;
				توڑو;
			حالت 'X':
				flags |= DP_F_اوپر;
			حالت 'x':
				flags |= DP_F_UNSIGNED;
				اگر (cflags == DP_C_SHORT)
					قدر = va_arg (دلائل, غیرعلامتی صحیح);
				ورنہ اگر (cflags == DP_C_LONG)
					قدر = (طویل)va_arg (دلائل, غیرعلامتی طویل صحیح);
				ورنہ اگر (cflags == DP_C_LLONG)
					قدر = (LLONG)va_arg (دلائل, غیرعلامتی LLONG);
				ورنہ اگر (cflags == DP_C_سائز)
					قدر = va_arg (دلائل, سائز_t);
#اگر_تعریف_شدہ notyet
				ورنہ اگر (cflags == DP_C_INTMAX)
					قدر = va_arg (دلائل, uintmax_t);
#اگر_ختم
				ورنہ
					قدر = (طویل)va_arg (دلائل, غیرعلامتی صحیح);
				اگر (fmtint(بفر, &currlen, maxlen, قدر,
				    16, min, max, flags) == -1)
					جاؤ fail;
				توڑو;
			حالت 'f':
				اگر (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (دلائل, LDOUBLE);
				ورنہ
					fvalue = va_arg (دلائل, دوہرا);
				اگر (fmtfp(بفر, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					جاؤ fail;
				توڑو;
			حالت 'E':
				flags |= DP_F_اوپر;
			حالت 'e':
				اگر (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (دلائل, LDOUBLE);
				ورنہ
					fvalue = va_arg (دلائل, دوہرا);
				اگر (fmtfp(بفر, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					جاؤ fail;
				توڑو;
			حالت 'G':
				flags |= DP_F_اوپر;
			حالت 'g':
				اگر (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (دلائل, LDOUBLE);
				ورنہ
					fvalue = va_arg (دلائل, دوہرا);
				اگر (fmtfp(بفر, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					جاؤ fail;
				توڑو;
			حالت 'c':
				DOPR_OUTCH(بفر, currlen, maxlen,
				    va_arg (دلائل, صحیح));
				توڑو;
			حالت 's':
				strvalue = va_arg (دلائل, حرف *);
				اگر (!strvalue) strvalue = "(NULL)";
				اگر (max == -1) {
					max = لڑی_لمبائی(strvalue);
				}
				اگر (min > 0 && max >= 0 && min > max) max = min;
				اگر (fmtstr(بفر, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					جاؤ fail;
				توڑو;
			حالت 'p':
				strvalue = va_arg (دلائل, خالی *);
				اگر (fmtint(بفر, &currlen, maxlen,
				    (طویل) strvalue, 16, min, max, flags) == -1)
					جاؤ fail;
				توڑو;
#اگر we_dont_want_this_اندر_openssh
			حالت 'n':
				اگر (cflags == DP_C_SHORT) {
					مختصر صحیح *عدد;
					عدد = va_arg (دلائل, مختصر صحیح *);
					*عدد = currlen;
				} ورنہ اگر (cflags == DP_C_LONG) {
					طویل صحیح *عدد;
					عدد = va_arg (دلائل, طویل صحیح *);
					*عدد = (طویل صحیح)currlen;
				} ورنہ اگر (cflags == DP_C_LLONG) {
					LLONG *عدد;
					عدد = va_arg (دلائل, LLONG *);
					*عدد = (LLONG)currlen;
				} ورنہ اگر (cflags == DP_C_سائز) {
					ssize_t *عدد;
					عدد = va_arg (دلائل, ssize_t *);
					*عدد = (ssize_t)currlen;
				} ورنہ اگر (cflags == DP_C_INTMAX) {
					intmax_t *عدد;
					عدد = va_arg (دلائل, intmax_t *);
					*عدد = (intmax_t)currlen;
				} ورنہ {
					صحیح *عدد;
					عدد = va_arg (دلائل, صحیح *);
					*عدد = currlen;
				}
				توڑو;
#اگر_ختم
			حالت '%':
				DOPR_OUTCH(بفر, currlen, maxlen, ch);
				توڑو;
			طےشدہ:
				/* Unknown, skip */
				توڑو;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			توڑو;
		حالت DP_S_مکمل:
			توڑو;
		طےشدہ:
			/* hmm? */
			توڑو; /* some picky compilers need this */
		}
	}
	اگر (maxlen != 0) {
		اگر (currlen < maxlen - 1)
			بفر[currlen] = '\0';
		ورنہ اگر (maxlen > 0)
			بفر[maxlen - 1] = '\0';
	}
	va_end(دلائل);
	واپس currlen < زیادہ_سے_زیادہ_عدد ? (صحیح)currlen : -1;
 fail:
	va_end(دلائل);
	واپس -1;
}

ساکن صحیح
fmtstr(حرف *بفر, سائز_t *currlen, سائز_t maxlen,
    حرف *قدر, صحیح flags, صحیح min, صحیح max)
{
	صحیح padlen, strln;     /* amount to pad */
	صحیح cnt = 0;

#اگر_تعریف_شدہ DEBUG_SNPRINTF
	لکھو("fmtstr min=%d max=%d s=[%s]\n", min, max, قدر);
#اگر_ختم
	اگر (قدر == 0) {
		قدر = "<NULL>";
	}

	برائے (strln = 0; strln < max && قدر[strln]; ++strln); /* strlen */
	padlen = min - strln;
	اگر (padlen < 0)
		padlen = 0;
	اگر (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	جب ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	جب (*قدر && (cnt < max)) {
		DOPR_OUTCH(بفر, *currlen, maxlen, *قدر);
		قدر++;
		++cnt;
	}
	جب ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	واپس 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

ساکن صحیح
fmtint(حرف *بفر, سائز_t *currlen, سائز_t maxlen,
    intmax_t قدر, صحیح بنیاد, صحیح min, صحیح max, صحیح flags)
{
	صحیح signvalue = 0;
	غیرعلامتی LLONG uvalue;
	حرف convert[20];
	صحیح رکھو = 0;
	صحیح spadlen = 0; /* amount to space pad */
	صحیح zpadlen = 0; /* amount to zero pad */
	صحیح caps = 0;

	اگر (max < 0)
		max = 0;

	uvalue = قدر;

	اگر(!(flags & DP_F_UNSIGNED)) {
		اگر( قدر < 0 ) {
			signvalue = '-';
			uvalue = -قدر;
		} ورنہ {
			اگر (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			ورنہ اگر (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	اگر (flags & DP_F_اوپر) caps = 1; /* Should characters be upper case? */

	کرو {
		convert[رکھو++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (غیرعلامتی)بنیاد  ];
		uvalue = (uvalue / (غیرعلامتی)بنیاد );
	} جب(uvalue && (رکھو < 20));
	اگر (رکھو == 20) رکھو--;
	convert[رکھو] = 0;

	zpadlen = max - رکھو;
	spadlen = min - MAX (max, رکھو) - (signvalue ? 1 : 0);
	اگر (zpadlen < 0) zpadlen = 0;
	اگر (spadlen < 0) spadlen = 0;
	اگر (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	اگر (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#اگر_تعریف_شدہ DEBUG_SNPRINTF
	لکھو("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, رکھو);
#اگر_ختم

	/* Spaces */
	جب (spadlen > 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	اگر (signvalue)
		DOPR_OUTCH(بفر, *currlen, maxlen, signvalue);

	/* Zeros */
	اگر (zpadlen > 0) {
		جب (zpadlen > 0) {
			DOPR_OUTCH(بفر, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	جب (رکھو > 0) {
		--رکھو;
		DOPR_OUTCH(بفر, *currlen, maxlen, convert[رکھو]);
	}

	/* Left Justified spaces */
	جب (spadlen < 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		++spadlen;
	}
	واپس 0;
}

ساکن LDOUBLE abs_val(LDOUBLE قدر)
{
	LDOUBLE نتیجہ = قدر;

	اگر (قدر < 0)
		نتیجہ = -قدر;

	واپس نتیجہ;
}

ساکن LDOUBLE POW10(صحیح val)
{
	LDOUBLE نتیجہ = 1;

	جب (val) {
		نتیجہ *= 10;
		val--;
	}

	واپس نتیجہ;
}

ساکن LLONG باری_2(LDOUBLE قدر)
{
	LLONG intpart;

	intpart = (LLONG)قدر;
	قدر = قدر - intpart;
	اگر (قدر >= 0.5) intpart++;

	واپس intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
ساکن دوہرا my_modf(دوہرا x0, دوہرا *iptr)
{
	صحیح i;
	طویل l;
	دوہرا x = x0;
	دوہرا f = 1.0;

	برائے (i=0;i<100;i++) {
		l = (طویل)x;
		اگر (l <= (x+1) && l >= (x-1)) توڑو;
		x *= 0.1;
		f *= 10.0;
	}

	اگر (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		واپس 0;
	}

	اگر (i != 0) {
		دوہرا i2;
		دوہرا ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		واپس ret;
	}

	(*iptr) = l;
	واپس x - (*iptr);
}


ساکن صحیح
fmtfp (حرف *بفر, سائز_t *currlen, سائز_t maxlen,
    LDOUBLE fvalue, صحیح min, صحیح max, صحیح flags)
{
	صحیح signvalue = 0;
	دوہرا ufvalue;
	حرف iconvert[311];
	حرف fconvert[311];
	صحیح iplace = 0;
	صحیح fplace = 0;
	صحیح padlen = 0; /* amount to pad */
	صحیح zpadlen = 0;
#اگر 0
	صحیح caps = 0;
#اگر_ختم
	صحیح idx;
	دوہرا intpart;
	دوہرا fracpart;
	دوہرا عارضی;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	اگر (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	اگر (fvalue < 0) {
		signvalue = '-';
	} ورنہ {
		اگر (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} ورنہ {
			اگر (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#اگر 0
	اگر (flags & DP_F_اوپر) caps = 1; /* Should characters be upper case? */
#اگر_ختم

#اگر 0
	 اگر (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#اگر_ختم

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	اگر (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	عارضی = ufvalue;
	my_modf(عارضی, &intpart);

	fracpart = باری_2((POW10(max)) * (ufvalue - intpart));

	اگر (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	کرو {
		عارضی = intpart*0.1;
		my_modf(عارضی, &intpart);
		idx = (صحیح) ((عارضی -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} جب (intpart && (iplace < 311));
	اگر (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	اگر (fracpart)
	{
		کرو {
			عارضی = fracpart*0.1;
			my_modf(عارضی, &fracpart);
			idx = (صحیح) ((عارضی -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} جب(fracpart && (fplace < 311));
		اگر (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	اگر (zpadlen < 0) zpadlen = 0;
	اگر (padlen < 0)
		padlen = 0;
	اگر (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	اگر ((flags & DP_F_ZERO) && (padlen > 0)) {
		اگر (signvalue) {
			DOPR_OUTCH(بفر, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		جب (padlen > 0) {
			DOPR_OUTCH(بفر, *currlen, maxlen, '0');
			--padlen;
		}
	}
	جب (padlen > 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		--padlen;
	}
	اگر (signvalue)
		DOPR_OUTCH(بفر, *currlen, maxlen, signvalue);

	جب (iplace > 0) {
		--iplace;
		DOPR_OUTCH(بفر, *currlen, maxlen, iconvert[iplace]);
	}

#اگر_تعریف_شدہ DEBUG_SNPRINTF
	لکھو("fmtfp: fplace=%d zpadlen=%d\n", fplace, zpadlen);
#اگر_ختم

	/*
	 * Decimal point.  This should probably use locale to find the correct
	 * char to print out.
	 */
	اگر (max > 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, '.');

		جب (zpadlen > 0) {
			DOPR_OUTCH(بفر, *currlen, maxlen, '0');
			--zpadlen;
		}

		جب (fplace > 0) {
			--fplace;
			DOPR_OUTCH(بفر, *currlen, maxlen, fconvert[fplace]);
		}
	}

	جب (padlen < 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		++padlen;
	}
	واپس 0;
}
#اگر_ختم /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#اگر !defined(HAVE_VSNPRINTF)
صحیح
vsnprintf (حرف *str, سائز_t گنتی, ثابت حرف *fmt, va_list دلائل)
{
	واپس dopr(str, گنتی, fmt, دلائل);
}
#اگر_ختم

#اگر !defined(HAVE_SNPRINTF)
صحیح
snprintf(حرف *str, سائز_t گنتی, SNPRINTF_CONST حرف *fmt, ...)
{
	سائز_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, گنتی, fmt, ap);
	va_end(ap);
	واپس ret;
}
#اگر_ختم
