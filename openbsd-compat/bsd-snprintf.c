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
#د_که_پای

#إذا !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#ضمن <ctype.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <limits.h>
#ضمن <errno.h>

#که_تعریف_شوی HAVE_LONG_DOUBLE
# define LDOUBLE اوږد مزدوج
#وإلا
# define LDOUBLE مزدوج
#د_که_پای

#که_تعریف_شوی HAVE_LONG_LONG
# define LLONG اوږد اوږد
#وإلا
# define LLONG اوږد
#د_که_پای

/*
 * dopr(): poor man's version of doprintf
 */

/* format read states */
#تعریف_کړه DP_S_DEFAULT 0
#تعریف_کړه DP_S_FLAGS   1
#تعریف_کړه DP_S_MIN     2
#تعریف_کړه DP_S_DOT     3
#تعریف_کړه DP_S_MAX     4
#تعریف_کړه DP_S_MOD     5
#تعریف_کړه DP_S_CONV    6
#تعریف_کړه DP_S_بشپړ    7

/* format flags - Bits */
#تعریف_کړه DP_F_MINUS	(1 << 0)
#تعریف_کړه DP_F_PLUS	(1 << 1)
#تعریف_کړه DP_F_SPACE	(1 << 2)
#تعریف_کړه DP_F_عدد	(1 << 3)
#تعریف_کړه DP_F_ZERO	(1 << 4)
#تعریف_کړه DP_F_پورته		(1 << 5)
#تعریف_کړه DP_F_UNSIGNED	(1 << 6)

/* Conversion Flags */
#تعریف_کړه DP_C_SHORT   1
#تعریف_کړه DP_C_LONG    2
#تعریف_کړه DP_C_LDOUBLE 3
#تعریف_کړه DP_C_LLONG   4
#تعریف_کړه DP_C_اندازه    5
#تعریف_کړه DP_C_INTMAX  6

#تعریف_کړه char_منزل_int(p) ((p)- '0')
#که_نه_تعریف_شوی MAX
# define MAX(p,q) (((p) >= (q)) ? (p) : (q))
#د_که_پای

#تعریف_کړه DOPR_OUTCH(buf, pos, buflen, thechar) \
	افعل { \
		إذا (pos + 1 >= لوی_عدد) { \
			errno = ERANGE; \
			أرجع -1; \
		} \
		إذا (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} طالما (0)

ساكن صحيح dopr(حرف *بفر, اندازه_t maxlen, ثابت حرف *format,
    va_list دلیلونه_دننه);
ساكن صحيح fmtstr(حرف *بفر, اندازه_t *currlen, اندازه_t maxlen,
    حرف *ارزښت, صحيح flags, صحيح min, صحيح max);
ساكن صحيح fmtint(حرف *بفر, اندازه_t *currlen, اندازه_t maxlen,
    intmax_t ارزښت, صحيح بنسټ, صحيح min, صحيح max, صحيح flags);
ساكن صحيح fmtfp(حرف *بفر, اندازه_t *currlen, اندازه_t maxlen,
    LDOUBLE fvalue, صحيح min, صحيح max, صحيح flags);

ساكن صحيح
dopr(حرف *بفر, اندازه_t maxlen, ثابت حرف *format, va_list دلیلونه_دننه)
{
	حرف ch;
	intmax_t ارزښت;
	LDOUBLE fvalue;
	حرف *strvalue;
	صحيح min;
	صحيح max;
	صحيح state;
	صحيح flags;
	صحيح cflags;
	اندازه_t currlen;
	va_list دلیلونه;

	VA_COPY(دلیلونه, دلیلونه_دننه);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	طالما (state != DP_S_بشپړ) {
		إذا (ch == '\0')
			state = DP_S_بشپړ;

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
				flags |= DP_F_عدد;
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
			إذا (که_عدد((بینښه حرف)ch)) {
				min = 10*min + char_منزل_int (ch);
				ch = *format++;
			} وإلا إذا (ch == '*') {
				min = va_arg (دلیلونه, صحيح);
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
			إذا (که_عدد((بینښه حرف)ch)) {
				إذا (max < 0)
					max = 0;
				max = 10*max + char_منزل_int (ch);
				ch = *format++;
			} وإلا إذا (ch == '*') {
				max = va_arg (دلیلونه, صحيح);
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
				cflags = DP_C_اندازه;
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
					ارزښت = va_arg (دلیلونه, صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					ارزښت = va_arg (دلیلونه, اوږد صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					ارزښت = va_arg (دلیلونه, LLONG);
				وإلا إذا (cflags == DP_C_اندازه)
					ارزښت = va_arg (دلیلونه, ssize_t);
				وإلا إذا (cflags == DP_C_INTMAX)
					ارزښت = va_arg (دلیلونه, intmax_t);
				وإلا
					ارزښت = va_arg (دلیلونه, صحيح);
				إذا (fmtint(بفر, &currlen, maxlen,
				    ارزښت, 10, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'o':
				flags |= DP_F_UNSIGNED;
				إذا (cflags == DP_C_SHORT)
					ارزښت = va_arg (دلیلونه, بینښه صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					ارزښت = (اوږد)va_arg (دلیلونه, بینښه اوږد صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					ارزښت = (اوږد)va_arg (دلیلونه, بینښه LLONG);
				وإلا إذا (cflags == DP_C_اندازه)
					ارزښت = va_arg (دلیلونه, اندازه_t);
#که_تعریف_شوی notyet
				وإلا إذا (cflags == DP_C_INTMAX)
					ارزښت = va_arg (دلیلونه, uintmax_t);
#د_که_پای
				وإلا
					ارزښت = (اوږد)va_arg (دلیلونه, بینښه صحيح);
				إذا (fmtint(بفر, &currlen, maxlen, ارزښت,
				    8, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'u':
				flags |= DP_F_UNSIGNED;
				إذا (cflags == DP_C_SHORT)
					ارزښت = va_arg (دلیلونه, بینښه صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					ارزښت = (اوږد)va_arg (دلیلونه, بینښه اوږد صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					ارزښت = (LLONG)va_arg (دلیلونه, بینښه LLONG);
				وإلا إذا (cflags == DP_C_اندازه)
					ارزښت = va_arg (دلیلونه, اندازه_t);
#که_تعریف_شوی notyet
				وإلا إذا (cflags == DP_C_INTMAX)
					ارزښت = va_arg (دلیلونه, uintmax_t);
#د_که_پای
				وإلا
					ارزښت = (اوږد)va_arg (دلیلونه, بینښه صحيح);
				إذا (fmtint(بفر, &currlen, maxlen, ارزښت,
				    10, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'X':
				flags |= DP_F_پورته;
			حالة 'x':
				flags |= DP_F_UNSIGNED;
				إذا (cflags == DP_C_SHORT)
					ارزښت = va_arg (دلیلونه, بینښه صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					ارزښت = (اوږد)va_arg (دلیلونه, بینښه اوږد صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					ارزښت = (LLONG)va_arg (دلیلونه, بینښه LLONG);
				وإلا إذا (cflags == DP_C_اندازه)
					ارزښت = va_arg (دلیلونه, اندازه_t);
#که_تعریف_شوی notyet
				وإلا إذا (cflags == DP_C_INTMAX)
					ارزښت = va_arg (دلیلونه, uintmax_t);
#د_که_پای
				وإلا
					ارزښت = (اوږد)va_arg (دلیلونه, بینښه صحيح);
				إذا (fmtint(بفر, &currlen, maxlen, ارزښت,
				    16, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'f':
				إذا (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (دلیلونه, LDOUBLE);
				وإلا
					fvalue = va_arg (دلیلونه, مزدوج);
				إذا (fmtfp(بفر, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'E':
				flags |= DP_F_پورته;
			حالة 'e':
				إذا (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (دلیلونه, LDOUBLE);
				وإلا
					fvalue = va_arg (دلیلونه, مزدوج);
				إذا (fmtfp(بفر, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'G':
				flags |= DP_F_پورته;
			حالة 'g':
				إذا (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (دلیلونه, LDOUBLE);
				وإلا
					fvalue = va_arg (دلیلونه, مزدوج);
				إذا (fmtfp(بفر, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'c':
				DOPR_OUTCH(بفر, currlen, maxlen,
				    va_arg (دلیلونه, صحيح));
				اكسر;
			حالة 's':
				strvalue = va_arg (دلیلونه, حرف *);
				إذا (!strvalue) strvalue = "(NULL)";
				إذا (max == -1) {
					max = مزي_اوږدوالی(strvalue);
				}
				إذا (min > 0 && max >= 0 && min > max) max = min;
				إذا (fmtstr(بفر, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					اذهب fail;
				اكسر;
			حالة 'p':
				strvalue = va_arg (دلیلونه, فراغ *);
				إذا (fmtint(بفر, &currlen, maxlen,
				    (اوږد) strvalue, 16, min, max, flags) == -1)
					اذهب fail;
				اكسر;
#إذا we_dont_want_this_دننه_openssh
			حالة 'n':
				إذا (cflags == DP_C_SHORT) {
					لنډ صحيح *عدد;
					عدد = va_arg (دلیلونه, لنډ صحيح *);
					*عدد = currlen;
				} وإلا إذا (cflags == DP_C_LONG) {
					اوږد صحيح *عدد;
					عدد = va_arg (دلیلونه, اوږد صحيح *);
					*عدد = (اوږد صحيح)currlen;
				} وإلا إذا (cflags == DP_C_LLONG) {
					LLONG *عدد;
					عدد = va_arg (دلیلونه, LLONG *);
					*عدد = (LLONG)currlen;
				} وإلا إذا (cflags == DP_C_اندازه) {
					ssize_t *عدد;
					عدد = va_arg (دلیلونه, ssize_t *);
					*عدد = (ssize_t)currlen;
				} وإلا إذا (cflags == DP_C_INTMAX) {
					intmax_t *عدد;
					عدد = va_arg (دلیلونه, intmax_t *);
					*عدد = (intmax_t)currlen;
				} وإلا {
					صحيح *عدد;
					عدد = va_arg (دلیلونه, صحيح *);
					*عدد = currlen;
				}
				اكسر;
#د_که_پای
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
		حالة DP_S_بشپړ:
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
	va_end(دلیلونه);
	أرجع currlen < لوی_عدد ? (صحيح)currlen : -1;
 fail:
	va_end(دلیلونه);
	أرجع -1;
}

ساكن صحيح
fmtstr(حرف *بفر, اندازه_t *currlen, اندازه_t maxlen,
    حرف *ارزښت, صحيح flags, صحيح min, صحيح max)
{
	صحيح padlen, strln;     /* amount to pad */
	صحيح cnt = 0;

#که_تعریف_شوی DEBUG_SNPRINTF
	چاپ_کړه("fmtstr min=%d max=%d s=[%s]\n", min, max, ارزښت);
#د_که_پای
	إذا (ارزښت == 0) {
		ارزښت = "<NULL>";
	}

	لكل (strln = 0; strln < max && ارزښت[strln]; ++strln); /* strlen */
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
	طالما (*ارزښت && (cnt < max)) {
		DOPR_OUTCH(بفر, *currlen, maxlen, *ارزښت);
		ارزښت++;
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
fmtint(حرف *بفر, اندازه_t *currlen, اندازه_t maxlen,
    intmax_t ارزښت, صحيح بنسټ, صحيح min, صحيح max, صحيح flags)
{
	صحيح signvalue = 0;
	بینښه LLONG uvalue;
	حرف convert[20];
	صحيح ځای_پرځای_کړه = 0;
	صحيح spadlen = 0; /* amount to space pad */
	صحيح zpadlen = 0; /* amount to zero pad */
	صحيح caps = 0;

	إذا (max < 0)
		max = 0;

	uvalue = ارزښت;

	إذا(!(flags & DP_F_UNSIGNED)) {
		إذا( ارزښت < 0 ) {
			signvalue = '-';
			uvalue = -ارزښت;
		} وإلا {
			إذا (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			وإلا إذا (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	إذا (flags & DP_F_پورته) caps = 1; /* Should characters be upper case? */

	افعل {
		convert[ځای_پرځای_کړه++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (بینښه)بنسټ  ];
		uvalue = (uvalue / (بینښه)بنسټ );
	} طالما(uvalue && (ځای_پرځای_کړه < 20));
	إذا (ځای_پرځای_کړه == 20) ځای_پرځای_کړه--;
	convert[ځای_پرځای_کړه] = 0;

	zpadlen = max - ځای_پرځای_کړه;
	spadlen = min - MAX (max, ځای_پرځای_کړه) - (signvalue ? 1 : 0);
	إذا (zpadlen < 0) zpadlen = 0;
	إذا (spadlen < 0) spadlen = 0;
	إذا (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	إذا (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#که_تعریف_شوی DEBUG_SNPRINTF
	چاپ_کړه("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, ځای_پرځای_کړه);
#د_که_پای

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
	طالما (ځای_پرځای_کړه > 0) {
		--ځای_پرځای_کړه;
		DOPR_OUTCH(بفر, *currlen, maxlen, convert[ځای_پرځای_کړه]);
	}

	/* Left Justified spaces */
	طالما (spadlen < 0) {
		DOPR_OUTCH(بفر, *currlen, maxlen, ' ');
		++spadlen;
	}
	أرجع 0;
}

ساكن LDOUBLE abs_val(LDOUBLE ارزښت)
{
	LDOUBLE پایله = ارزښت;

	إذا (ارزښت < 0)
		پایله = -ارزښت;

	أرجع پایله;
}

ساكن LDOUBLE POW10(صحيح val)
{
	LDOUBLE پایله = 1;

	طالما (val) {
		پایله *= 10;
		val--;
	}

	أرجع پایله;
}

ساكن LLONG پړاو_2(LDOUBLE ارزښت)
{
	LLONG intpart;

	intpart = (LLONG)ارزښت;
	ارزښت = ارزښت - intpart;
	إذا (ارزښت >= 0.5) intpart++;

	أرجع intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
ساكن مزدوج my_modf(مزدوج x0, مزدوج *iptr)
{
	صحيح i;
	اوږد l;
	مزدوج x = x0;
	مزدوج f = 1.0;

	لكل (i=0;i<100;i++) {
		l = (اوږد)x;
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
fmtfp (حرف *بفر, اندازه_t *currlen, اندازه_t maxlen,
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
#د_که_پای
	صحيح idx;
	مزدوج intpart;
	مزدوج fracpart;
	مزدوج لنډمهاله;

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
	إذا (flags & DP_F_پورته) caps = 1; /* Should characters be upper case? */
#د_که_پای

#إذا 0
	 إذا (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#د_که_پای

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	إذا (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	لنډمهاله = ufvalue;
	my_modf(لنډمهاله, &intpart);

	fracpart = پړاو_2((POW10(max)) * (ufvalue - intpart));

	إذا (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	افعل {
		لنډمهاله = intpart*0.1;
		my_modf(لنډمهاله, &intpart);
		idx = (صحيح) ((لنډمهاله -intpart +0.05)* 10.0);
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
			لنډمهاله = fracpart*0.1;
			my_modf(لنډمهاله, &fracpart);
			idx = (صحيح) ((لنډمهاله -fracpart +0.05)* 10.0);
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

#که_تعریف_شوی DEBUG_SNPRINTF
	چاپ_کړه("fmtfp: fplace=%d zpadlen=%d\n", fplace, zpadlen);
#د_که_پای

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
#د_که_پای /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#إذا !defined(HAVE_VSNPRINTF)
صحيح
vsnprintf (حرف *str, اندازه_t شمېر, ثابت حرف *fmt, va_list دلیلونه)
{
	أرجع dopr(str, شمېر, fmt, دلیلونه);
}
#د_که_پای

#إذا !defined(HAVE_SNPRINTF)
صحيح
snprintf(حرف *str, اندازه_t شمېر, SNPRINTF_CONST حرف *fmt, ...)
{
	اندازه_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, شمېر, fmt, ap);
	va_end(ap);
	أرجع ret;
}
#د_که_پای
