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

#якщо defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#якщо !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long double
#інакше
# define LDOUBLE double
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#інакше
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
		якщо (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			повернути -1; \
		} \
		якщо (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} поки (0)

static ціле dopr(char *buffer, size_t maxlen, const char *format,
    va_list args_in);
static ціле fmtstr(char *buffer, size_t *currlen, size_t maxlen,
    char *value, ціле flags, ціле min, ціле max);
static ціле fmtint(char *buffer, size_t *currlen, size_t maxlen,
    intmax_t value, ціле base, ціле min, ціле max, ціле flags);
static ціле fmtfp(char *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, ціле min, ціле max, ціле flags);

static ціле
dopr(char *buffer, size_t maxlen, const char *format, va_list args_in)
{
	char ch;
	intmax_t value;
	LDOUBLE fvalue;
	char *strvalue;
	ціле min;
	ціле max;
	ціле state;
	ціле flags;
	ціле cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	поки (state != DP_S_DONE) {
		якщо (ch == '\0')
			state = DP_S_DONE;

		switch(state) {
		case DP_S_DEFAULT:
			якщо (ch == '%')
				state = DP_S_FLAGS;
			інакше
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			break;
		case DP_S_FLAGS:
			switch (ch) {
			case '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				break;
			case '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				break;
			case ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				break;
			case '#':
				flags |= DP_F_NUM;
				ch = *format++;
				break;
			case '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				break;
			default:
				state = DP_S_MIN;
				break;
			}
			break;
		case DP_S_MIN:
			якщо (isdigit((unsigned char)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} інакше якщо (ch == '*') {
				min = va_arg (args, ціле);
				ch = *format++;
				state = DP_S_DOT;
			} інакше {
				state = DP_S_DOT;
			}
			break;
		case DP_S_DOT:
			якщо (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} інакше {
				state = DP_S_MOD;
			}
			break;
		case DP_S_MAX:
			якщо (isdigit((unsigned char)ch)) {
				якщо (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} інакше якщо (ch == '*') {
				max = va_arg (args, ціле);
				ch = *format++;
				state = DP_S_MOD;
			} інакше {
				state = DP_S_MOD;
			}
			break;
		case DP_S_MOD:
			switch (ch) {
			case 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				break;
			case 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				break;
			case 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				якщо (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				break;
			case 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				break;
			case 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				break;
			default:
				break;
			}
			state = DP_S_CONV;
			break;
		case DP_S_CONV:
			switch (ch) {
			case 'd':
			case 'i':
				якщо (cflags == DP_C_SHORT)
					value = va_arg (args, ціле);
				інакше якщо (cflags == DP_C_LONG)
					value = va_arg (args, long ціле);
				інакше якщо (cflags == DP_C_LLONG)
					value = va_arg (args, LLONG);
				інакше якщо (cflags == DP_C_SIZE)
					value = va_arg (args, ssize_t);
				інакше якщо (cflags == DP_C_INTMAX)
					value = va_arg (args, intmax_t);
				інакше
					value = va_arg (args, ціле);
				якщо (fmtint(buffer, &currlen, maxlen,
				    value, 10, min, max, flags) == -1)
					goto fail;
				break;
			case 'o':
				flags |= DP_F_UNSIGNED;
				якщо (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned ціле);
				інакше якщо (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long ціле);
				інакше якщо (cflags == DP_C_LLONG)
					value = (long)va_arg (args, unsigned LLONG);
				інакше якщо (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				інакше якщо (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				інакше
					value = (long)va_arg (args, unsigned ціле);
				якщо (fmtint(buffer, &currlen, maxlen, value,
				    8, min, max, flags) == -1)
					goto fail;
				break;
			case 'u':
				flags |= DP_F_UNSIGNED;
				якщо (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned ціле);
				інакше якщо (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long ціле);
				інакше якщо (cflags == DP_C_LLONG)
					value = (LLONG)va_arg (args, unsigned LLONG);
				інакше якщо (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				інакше якщо (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				інакше
					value = (long)va_arg (args, unsigned ціле);
				якщо (fmtint(buffer, &currlen, maxlen, value,
				    10, min, max, flags) == -1)
					goto fail;
				break;
			case 'X':
				flags |= DP_F_UP;
			case 'x':
				flags |= DP_F_UNSIGNED;
				якщо (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned ціле);
				інакше якщо (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long ціле);
				інакше якщо (cflags == DP_C_LLONG)
					value = (LLONG)va_arg (args, unsigned LLONG);
				інакше якщо (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				інакше якщо (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				інакше
					value = (long)va_arg (args, unsigned ціле);
				якщо (fmtint(buffer, &currlen, maxlen, value,
				    16, min, max, flags) == -1)
					goto fail;
				break;
			case 'f':
				якщо (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				інакше
					fvalue = va_arg (args, double);
				якщо (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				break;
			case 'E':
				flags |= DP_F_UP;
			case 'e':
				якщо (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				інакше
					fvalue = va_arg (args, double);
				якщо (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				break;
			case 'G':
				flags |= DP_F_UP;
			case 'g':
				якщо (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				інакше
					fvalue = va_arg (args, double);
				якщо (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				break;
			case 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, ціле));
				break;
			case 's':
				strvalue = va_arg (args, char *);
				якщо (!strvalue) strvalue = "(NULL)";
				якщо (max == -1) {
					max = strlen(strvalue);
				}
				якщо (min > 0 && max >= 0 && min > max) max = min;
				якщо (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					goto fail;
				break;
			case 'p':
				strvalue = va_arg (args, void *);
				якщо (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					goto fail;
				break;
#якщо we_dont_want_this_in_openssh
			case 'n':
				якщо (cflags == DP_C_SHORT) {
					short ціле *num;
					num = va_arg (args, short ціле *);
					*num = currlen;
				} інакше якщо (cflags == DP_C_LONG) {
					long ціле *num;
					num = va_arg (args, long ціле *);
					*num = (long ціле)currlen;
				} інакше якщо (cflags == DP_C_LLONG) {
					LLONG *num;
					num = va_arg (args, LLONG *);
					*num = (LLONG)currlen;
				} інакше якщо (cflags == DP_C_SIZE) {
					ssize_t *num;
					num = va_arg (args, ssize_t *);
					*num = (ssize_t)currlen;
				} інакше якщо (cflags == DP_C_INTMAX) {
					intmax_t *num;
					num = va_arg (args, intmax_t *);
					*num = (intmax_t)currlen;
				} інакше {
					ціле *num;
					num = va_arg (args, ціле *);
					*num = currlen;
				}
				break;
#endif
			case '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				break;
			default:
				/* Unknown, skip */
				break;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			break;
		case DP_S_DONE:
			break;
		default:
			/* hmm? */
			break; /* some picky compilers need this */
		}
	}
	якщо (maxlen != 0) {
		якщо (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		інакше якщо (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	повернути currlen < INT_MAX ? (ціле)currlen : -1;
 fail:
	va_end(args);
	повернути -1;
}

static ціле
fmtstr(char *buffer, size_t *currlen, size_t maxlen,
    char *value, ціле flags, ціле min, ціле max)
{
	ціле padlen, strln;     /* amount to pad */
	ціле cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, value);
#endif
	якщо (value == 0) {
		value = "<NULL>";
	}

	для (strln = 0; strln < max && value[strln]; ++strln); /* strlen */
	padlen = min - strln;
	якщо (padlen < 0)
		padlen = 0;
	якщо (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	поки ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	поки (*value && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *value);
		value++;
		++cnt;
	}
	поки ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	повернути 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

static ціле
fmtint(char *buffer, size_t *currlen, size_t maxlen,
    intmax_t value, ціле base, ціле min, ціле max, ціле flags)
{
	ціле signvalue = 0;
	unsigned LLONG uvalue;
	char convert[20];
	ціле place = 0;
	ціле spadlen = 0; /* amount to space pad */
	ціле zpadlen = 0; /* amount to zero pad */
	ціле caps = 0;

	якщо (max < 0)
		max = 0;

	uvalue = value;

	якщо(!(flags & DP_F_UNSIGNED)) {
		якщо( value < 0 ) {
			signvalue = '-';
			uvalue = -value;
		} інакше {
			якщо (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			інакше якщо (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	якщо (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	do {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} поки(uvalue && (place < 20));
	якщо (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	якщо (zpadlen < 0) zpadlen = 0;
	якщо (spadlen < 0) spadlen = 0;
	якщо (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	якщо (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	поки (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	якщо (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	якщо (zpadlen > 0) {
		поки (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	поки (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	поки (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	повернути 0;
}

static LDOUBLE abs_val(LDOUBLE value)
{
	LDOUBLE result = value;

	якщо (value < 0)
		result = -value;

	повернути result;
}

static LDOUBLE POW10(ціле val)
{
	LDOUBLE result = 1;

	поки (val) {
		result *= 10;
		val--;
	}

	повернути result;
}

static LLONG ROUND(LDOUBLE value)
{
	LLONG intpart;

	intpart = (LLONG)value;
	value = value - intpart;
	якщо (value >= 0.5) intpart++;

	повернути intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
static double my_modf(double x0, double *iptr)
{
	ціле i;
	long l;
	double x = x0;
	double f = 1.0;

	для (i=0;i<100;i++) {
		l = (long)x;
		якщо (l <= (x+1) && l >= (x-1)) break;
		x *= 0.1;
		f *= 10.0;
	}

	якщо (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		повернути 0;
	}

	якщо (i != 0) {
		double i2;
		double ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		повернути ret;
	}

	(*iptr) = l;
	повернути x - (*iptr);
}


static ціле
fmtfp (char *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, ціле min, ціле max, ціле flags)
{
	ціле signvalue = 0;
	double ufvalue;
	char iconvert[311];
	char fconvert[311];
	ціле iplace = 0;
	ціле fplace = 0;
	ціле padlen = 0; /* amount to pad */
	ціле zpadlen = 0;
#якщо 0
	ціле caps = 0;
#endif
	ціле idx;
	double intpart;
	double fracpart;
	double temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	якщо (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	якщо (fvalue < 0) {
		signvalue = '-';
	} інакше {
		якщо (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} інакше {
			якщо (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#якщо 0
	якщо (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#якщо 0
	 якщо (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	якщо (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	якщо (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	do {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (ціле) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} поки (intpart && (iplace < 311));
	якщо (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	якщо (fracpart)
	{
		do {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (ціле) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} поки(fracpart && (fplace < 311));
		якщо (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	якщо (zpadlen < 0) zpadlen = 0;
	якщо (padlen < 0)
		padlen = 0;
	якщо (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	якщо ((flags & DP_F_ZERO) && (padlen > 0)) {
		якщо (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		поки (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	поки (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	якщо (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	поки (iplace > 0) {
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
	якщо (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		поки (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		поки (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	поки (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	повернути 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#якщо !defined(HAVE_VSNPRINTF)
ціле
vsnprintf (char *str, size_t count, const char *fmt, va_list args)
{
	повернути dopr(str, count, fmt, args);
}
#endif

#якщо !defined(HAVE_SNPRINTF)
ціле
snprintf(char *str, size_t count, SNPRINTF_CONST char *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, count, fmt, ap);
	va_end(ap);
	повернути ret;
}
#endif
