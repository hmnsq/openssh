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
#endif

#إذا !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#ضمن <ctype.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <limits.h>
#ضمن <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long مزدوج
#وإلا
# define LDOUBLE مزدوج
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#وإلا
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
#define DP_F_اڠک	(1 << 3)
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
	افعل { \
		إذا (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			أرجع -1; \
		} \
		إذا (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} طالما (0)

ساكن صحيح dopr(حرف *buffer, size_t maxlen, ثابت حرف *format,
    va_list args_in);
ساكن صحيح fmtstr(حرف *buffer, size_t *currlen, size_t maxlen,
    حرف *نيلاي, صحيح flags, صحيح min, صحيح max);
ساكن صحيح fmtint(حرف *buffer, size_t *currlen, size_t maxlen,
    intmax_t نيلاي, صحيح base, صحيح min, صحيح max, صحيح flags);
ساكن صحيح fmtfp(حرف *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, صحيح min, صحيح max, صحيح flags);

ساكن صحيح
dopr(حرف *buffer, size_t maxlen, ثابت حرف *format, va_list args_in)
{
	حرف ch;
	intmax_t نيلاي;
	LDOUBLE fvalue;
	حرف *strvalue;
	صحيح min;
	صحيح max;
	صحيح state;
	صحيح flags;
	صحيح cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	طالما (state != DP_S_DONE) {
		إذا (ch == '\0')
			state = DP_S_DONE;

		بدل(state) {
		حالة DP_S_DEFAULT:
			إذا (ch == '%')
				state = DP_S_FLAGS;
			وإلا
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
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
				flags |= DP_F_اڠک;
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
			إذا (isdigit((unsigned حرف)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} وإلا إذا (ch == '*') {
				min = va_arg (args, صحيح);
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
			إذا (isdigit((unsigned حرف)ch)) {
				إذا (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} وإلا إذا (ch == '*') {
				max = va_arg (args, صحيح);
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
				cflags = DP_C_SIZE;
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
					نيلاي = va_arg (args, صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					نيلاي = va_arg (args, long صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					نيلاي = va_arg (args, LLONG);
				وإلا إذا (cflags == DP_C_SIZE)
					نيلاي = va_arg (args, ssize_t);
				وإلا إذا (cflags == DP_C_INTMAX)
					نيلاي = va_arg (args, intmax_t);
				وإلا
					نيلاي = va_arg (args, صحيح);
				إذا (fmtint(buffer, &currlen, maxlen,
				    نيلاي, 10, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'o':
				flags |= DP_F_UNSIGNED;
				إذا (cflags == DP_C_SHORT)
					نيلاي = va_arg (args, unsigned صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					نيلاي = (long)va_arg (args, unsigned long صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					نيلاي = (long)va_arg (args, unsigned LLONG);
				وإلا إذا (cflags == DP_C_SIZE)
					نيلاي = va_arg (args, size_t);
#ifdef notyet
				وإلا إذا (cflags == DP_C_INTMAX)
					نيلاي = va_arg (args, uintmax_t);
#endif
				وإلا
					نيلاي = (long)va_arg (args, unsigned صحيح);
				إذا (fmtint(buffer, &currlen, maxlen, نيلاي,
				    8, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'u':
				flags |= DP_F_UNSIGNED;
				إذا (cflags == DP_C_SHORT)
					نيلاي = va_arg (args, unsigned صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					نيلاي = (long)va_arg (args, unsigned long صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					نيلاي = (LLONG)va_arg (args, unsigned LLONG);
				وإلا إذا (cflags == DP_C_SIZE)
					نيلاي = va_arg (args, size_t);
#ifdef notyet
				وإلا إذا (cflags == DP_C_INTMAX)
					نيلاي = va_arg (args, uintmax_t);
#endif
				وإلا
					نيلاي = (long)va_arg (args, unsigned صحيح);
				إذا (fmtint(buffer, &currlen, maxlen, نيلاي,
				    10, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'X':
				flags |= DP_F_UP;
			حالة 'x':
				flags |= DP_F_UNSIGNED;
				إذا (cflags == DP_C_SHORT)
					نيلاي = va_arg (args, unsigned صحيح);
				وإلا إذا (cflags == DP_C_LONG)
					نيلاي = (long)va_arg (args, unsigned long صحيح);
				وإلا إذا (cflags == DP_C_LLONG)
					نيلاي = (LLONG)va_arg (args, unsigned LLONG);
				وإلا إذا (cflags == DP_C_SIZE)
					نيلاي = va_arg (args, size_t);
#ifdef notyet
				وإلا إذا (cflags == DP_C_INTMAX)
					نيلاي = va_arg (args, uintmax_t);
#endif
				وإلا
					نيلاي = (long)va_arg (args, unsigned صحيح);
				إذا (fmtint(buffer, &currlen, maxlen, نيلاي,
				    16, min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'f':
				إذا (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				وإلا
					fvalue = va_arg (args, مزدوج);
				إذا (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'E':
				flags |= DP_F_UP;
			حالة 'e':
				إذا (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				وإلا
					fvalue = va_arg (args, مزدوج);
				إذا (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'G':
				flags |= DP_F_UP;
			حالة 'g':
				إذا (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				وإلا
					fvalue = va_arg (args, مزدوج);
				إذا (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					اذهب fail;
				اكسر;
			حالة 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, صحيح));
				اكسر;
			حالة 's':
				strvalue = va_arg (args, حرف *);
				إذا (!strvalue) strvalue = "(NULL)";
				إذا (max == -1) {
					max = strlen(strvalue);
				}
				إذا (min > 0 && max >= 0 && min > max) max = min;
				إذا (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					اذهب fail;
				اكسر;
			حالة 'p':
				strvalue = va_arg (args, فراغ *);
				إذا (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					اذهب fail;
				اكسر;
#إذا we_dont_want_this_in_openssh
			حالة 'n':
				إذا (cflags == DP_C_SHORT) {
					short صحيح *اڠک;
					اڠک = va_arg (args, short صحيح *);
					*اڠک = currlen;
				} وإلا إذا (cflags == DP_C_LONG) {
					long صحيح *اڠک;
					اڠک = va_arg (args, long صحيح *);
					*اڠک = (long صحيح)currlen;
				} وإلا إذا (cflags == DP_C_LLONG) {
					LLONG *اڠک;
					اڠک = va_arg (args, LLONG *);
					*اڠک = (LLONG)currlen;
				} وإلا إذا (cflags == DP_C_SIZE) {
					ssize_t *اڠک;
					اڠک = va_arg (args, ssize_t *);
					*اڠک = (ssize_t)currlen;
				} وإلا إذا (cflags == DP_C_INTMAX) {
					intmax_t *اڠک;
					اڠک = va_arg (args, intmax_t *);
					*اڠک = (intmax_t)currlen;
				} وإلا {
					صحيح *اڠک;
					اڠک = va_arg (args, صحيح *);
					*اڠک = currlen;
				}
				اكسر;
#endif
			حالة '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
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
		حالة DP_S_DONE:
			اكسر;
		افتراضي:
			/* hmm? */
			اكسر; /* some picky compilers need this */
		}
	}
	إذا (maxlen != 0) {
		إذا (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		وإلا إذا (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	أرجع currlen < INT_MAX ? (صحيح)currlen : -1;
 fail:
	va_end(args);
	أرجع -1;
}

ساكن صحيح
fmtstr(حرف *buffer, size_t *currlen, size_t maxlen,
    حرف *نيلاي, صحيح flags, صحيح min, صحيح max)
{
	صحيح padlen, strln;     /* amount to pad */
	صحيح cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, نيلاي);
#endif
	إذا (نيلاي == 0) {
		نيلاي = "<NULL>";
	}

	لكل (strln = 0; strln < max && نيلاي[strln]; ++strln); /* strlen */
	padlen = min - strln;
	إذا (padlen < 0)
		padlen = 0;
	إذا (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	طالما ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	طالما (*نيلاي && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *نيلاي);
		نيلاي++;
		++cnt;
	}
	طالما ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	أرجع 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

ساكن صحيح
fmtint(حرف *buffer, size_t *currlen, size_t maxlen,
    intmax_t نيلاي, صحيح base, صحيح min, صحيح max, صحيح flags)
{
	صحيح signvalue = 0;
	unsigned LLONG uvalue;
	حرف convert[20];
	صحيح place = 0;
	صحيح spadlen = 0; /* amount to space pad */
	صحيح zpadlen = 0; /* amount to zero pad */
	صحيح caps = 0;

	إذا (max < 0)
		max = 0;

	uvalue = نيلاي;

	إذا(!(flags & DP_F_UNSIGNED)) {
		إذا( نيلاي < 0 ) {
			signvalue = '-';
			uvalue = -نيلاي;
		} وإلا {
			إذا (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			وإلا إذا (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	إذا (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	افعل {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} طالما(uvalue && (place < 20));
	إذا (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	إذا (zpadlen < 0) zpadlen = 0;
	إذا (spadlen < 0) spadlen = 0;
	إذا (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	إذا (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	طالما (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	إذا (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	إذا (zpadlen > 0) {
		طالما (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	طالما (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	طالما (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	أرجع 0;
}

ساكن LDOUBLE abs_val(LDOUBLE نيلاي)
{
	LDOUBLE result = نيلاي;

	إذا (نيلاي < 0)
		result = -نيلاي;

	أرجع result;
}

ساكن LDOUBLE POW10(صحيح val)
{
	LDOUBLE result = 1;

	طالما (val) {
		result *= 10;
		val--;
	}

	أرجع result;
}

ساكن LLONG ROUND(LDOUBLE نيلاي)
{
	LLONG intpart;

	intpart = (LLONG)نيلاي;
	نيلاي = نيلاي - intpart;
	إذا (نيلاي >= 0.5) intpart++;

	أرجع intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
ساكن مزدوج my_modf(مزدوج x0, مزدوج *iptr)
{
	صحيح i;
	long l;
	مزدوج x = x0;
	مزدوج f = 1.0;

	لكل (i=0;i<100;i++) {
		l = (long)x;
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
fmtfp (حرف *buffer, size_t *currlen, size_t maxlen,
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
#endif
	صحيح idx;
	مزدوج intpart;
	مزدوج fracpart;
	مزدوج temp;

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
	إذا (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#إذا 0
	 إذا (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	إذا (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	إذا (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	افعل {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (صحيح) ((temp -intpart +0.05)* 10.0);
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
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (صحيح) ((temp -fracpart +0.05)* 10.0);
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
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		طالما (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	طالما (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	إذا (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	طالما (iplace > 0) {
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
	إذا (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		طالما (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		طالما (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	طالما (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	أرجع 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#إذا !defined(HAVE_VSNPRINTF)
صحيح
vsnprintf (حرف *str, size_t کيراءن, ثابت حرف *fmt, va_list args)
{
	أرجع dopr(str, کيراءن, fmt, args);
}
#endif

#إذا !defined(HAVE_SNPRINTF)
صحيح
snprintf(حرف *str, size_t کيراءن, SNPRINTF_CONST حرف *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, کيراءن, fmt, ap);
	va_end(ap);
	أرجع ret;
}
#endif
