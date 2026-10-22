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

#если defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#если !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long double
#иначе
# define LDOUBLE double
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#иначе
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
		если (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			вернуть -1; \
		} \
		если (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} пока (0)

static целое dopr(char *buffer, size_t maxlen, const char *format,
    va_list args_in);
static целое fmtstr(char *buffer, size_t *currlen, size_t maxlen,
    char *value, целое flags, целое min, целое max);
static целое fmtint(char *buffer, size_t *currlen, size_t maxlen,
    intmax_t value, целое base, целое min, целое max, целое flags);
static целое fmtfp(char *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, целое min, целое max, целое flags);

static целое
dopr(char *buffer, size_t maxlen, const char *format, va_list args_in)
{
	char ch;
	intmax_t value;
	LDOUBLE fvalue;
	char *strvalue;
	целое min;
	целое max;
	целое state;
	целое flags;
	целое cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	пока (state != DP_S_DONE) {
		если (ch == '\0')
			state = DP_S_DONE;

		switch(state) {
		case DP_S_DEFAULT:
			если (ch == '%')
				state = DP_S_FLAGS;
			иначе
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
			если (isdigit((unsigned char)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} иначе если (ch == '*') {
				min = va_arg (args, целое);
				ch = *format++;
				state = DP_S_DOT;
			} иначе {
				state = DP_S_DOT;
			}
			break;
		case DP_S_DOT:
			если (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} иначе {
				state = DP_S_MOD;
			}
			break;
		case DP_S_MAX:
			если (isdigit((unsigned char)ch)) {
				если (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} иначе если (ch == '*') {
				max = va_arg (args, целое);
				ch = *format++;
				state = DP_S_MOD;
			} иначе {
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
				если (ch == 'l') {	/* It's a long long */
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
				если (cflags == DP_C_SHORT)
					value = va_arg (args, целое);
				иначе если (cflags == DP_C_LONG)
					value = va_arg (args, long целое);
				иначе если (cflags == DP_C_LLONG)
					value = va_arg (args, LLONG);
				иначе если (cflags == DP_C_SIZE)
					value = va_arg (args, ssize_t);
				иначе если (cflags == DP_C_INTMAX)
					value = va_arg (args, intmax_t);
				иначе
					value = va_arg (args, целое);
				если (fmtint(buffer, &currlen, maxlen,
				    value, 10, min, max, flags) == -1)
					goto fail;
				break;
			case 'o':
				flags |= DP_F_UNSIGNED;
				если (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned целое);
				иначе если (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long целое);
				иначе если (cflags == DP_C_LLONG)
					value = (long)va_arg (args, unsigned LLONG);
				иначе если (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				иначе если (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				иначе
					value = (long)va_arg (args, unsigned целое);
				если (fmtint(buffer, &currlen, maxlen, value,
				    8, min, max, flags) == -1)
					goto fail;
				break;
			case 'u':
				flags |= DP_F_UNSIGNED;
				если (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned целое);
				иначе если (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long целое);
				иначе если (cflags == DP_C_LLONG)
					value = (LLONG)va_arg (args, unsigned LLONG);
				иначе если (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				иначе если (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				иначе
					value = (long)va_arg (args, unsigned целое);
				если (fmtint(buffer, &currlen, maxlen, value,
				    10, min, max, flags) == -1)
					goto fail;
				break;
			case 'X':
				flags |= DP_F_UP;
			case 'x':
				flags |= DP_F_UNSIGNED;
				если (cflags == DP_C_SHORT)
					value = va_arg (args, unsigned целое);
				иначе если (cflags == DP_C_LONG)
					value = (long)va_arg (args, unsigned long целое);
				иначе если (cflags == DP_C_LLONG)
					value = (LLONG)va_arg (args, unsigned LLONG);
				иначе если (cflags == DP_C_SIZE)
					value = va_arg (args, size_t);
#ifdef notyet
				иначе если (cflags == DP_C_INTMAX)
					value = va_arg (args, uintmax_t);
#endif
				иначе
					value = (long)va_arg (args, unsigned целое);
				если (fmtint(buffer, &currlen, maxlen, value,
				    16, min, max, flags) == -1)
					goto fail;
				break;
			case 'f':
				если (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				иначе
					fvalue = va_arg (args, double);
				если (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				break;
			case 'E':
				flags |= DP_F_UP;
			case 'e':
				если (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				иначе
					fvalue = va_arg (args, double);
				если (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				break;
			case 'G':
				flags |= DP_F_UP;
			case 'g':
				если (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				иначе
					fvalue = va_arg (args, double);
				если (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					goto fail;
				break;
			case 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, целое));
				break;
			case 's':
				strvalue = va_arg (args, char *);
				если (!strvalue) strvalue = "(NULL)";
				если (max == -1) {
					max = strlen(strvalue);
				}
				если (min > 0 && max >= 0 && min > max) max = min;
				если (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					goto fail;
				break;
			case 'p':
				strvalue = va_arg (args, void *);
				если (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					goto fail;
				break;
#если we_dont_want_this_in_openssh
			case 'n':
				если (cflags == DP_C_SHORT) {
					short целое *num;
					num = va_arg (args, short целое *);
					*num = currlen;
				} иначе если (cflags == DP_C_LONG) {
					long целое *num;
					num = va_arg (args, long целое *);
					*num = (long целое)currlen;
				} иначе если (cflags == DP_C_LLONG) {
					LLONG *num;
					num = va_arg (args, LLONG *);
					*num = (LLONG)currlen;
				} иначе если (cflags == DP_C_SIZE) {
					ssize_t *num;
					num = va_arg (args, ssize_t *);
					*num = (ssize_t)currlen;
				} иначе если (cflags == DP_C_INTMAX) {
					intmax_t *num;
					num = va_arg (args, intmax_t *);
					*num = (intmax_t)currlen;
				} иначе {
					целое *num;
					num = va_arg (args, целое *);
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
	если (maxlen != 0) {
		если (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		иначе если (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	вернуть currlen < INT_MAX ? (целое)currlen : -1;
 fail:
	va_end(args);
	вернуть -1;
}

static целое
fmtstr(char *buffer, size_t *currlen, size_t maxlen,
    char *value, целое flags, целое min, целое max)
{
	целое padlen, strln;     /* amount to pad */
	целое cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, value);
#endif
	если (value == 0) {
		value = "<NULL>";
	}

	для (strln = 0; strln < max && value[strln]; ++strln); /* strlen */
	padlen = min - strln;
	если (padlen < 0)
		padlen = 0;
	если (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	пока ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	пока (*value && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *value);
		value++;
		++cnt;
	}
	пока ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	вернуть 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

static целое
fmtint(char *buffer, size_t *currlen, size_t maxlen,
    intmax_t value, целое base, целое min, целое max, целое flags)
{
	целое signvalue = 0;
	unsigned LLONG uvalue;
	char convert[20];
	целое place = 0;
	целое spadlen = 0; /* amount to space pad */
	целое zpadlen = 0; /* amount to zero pad */
	целое caps = 0;

	если (max < 0)
		max = 0;

	uvalue = value;

	если(!(flags & DP_F_UNSIGNED)) {
		если( value < 0 ) {
			signvalue = '-';
			uvalue = -value;
		} иначе {
			если (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			иначе если (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	если (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	do {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} пока(uvalue && (place < 20));
	если (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	если (zpadlen < 0) zpadlen = 0;
	если (spadlen < 0) spadlen = 0;
	если (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	если (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	пока (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	если (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	если (zpadlen > 0) {
		пока (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	пока (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	пока (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	вернуть 0;
}

static LDOUBLE abs_val(LDOUBLE value)
{
	LDOUBLE result = value;

	если (value < 0)
		result = -value;

	вернуть result;
}

static LDOUBLE POW10(целое val)
{
	LDOUBLE result = 1;

	пока (val) {
		result *= 10;
		val--;
	}

	вернуть result;
}

static LLONG ROUND(LDOUBLE value)
{
	LLONG intpart;

	intpart = (LLONG)value;
	value = value - intpart;
	если (value >= 0.5) intpart++;

	вернуть intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
static double my_modf(double x0, double *iptr)
{
	целое i;
	long l;
	double x = x0;
	double f = 1.0;

	для (i=0;i<100;i++) {
		l = (long)x;
		если (l <= (x+1) && l >= (x-1)) break;
		x *= 0.1;
		f *= 10.0;
	}

	если (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		вернуть 0;
	}

	если (i != 0) {
		double i2;
		double ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		вернуть ret;
	}

	(*iptr) = l;
	вернуть x - (*iptr);
}


static целое
fmtfp (char *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, целое min, целое max, целое flags)
{
	целое signvalue = 0;
	double ufvalue;
	char iconvert[311];
	char fconvert[311];
	целое iplace = 0;
	целое fplace = 0;
	целое padlen = 0; /* amount to pad */
	целое zpadlen = 0;
#если 0
	целое caps = 0;
#endif
	целое idx;
	double intpart;
	double fracpart;
	double temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	если (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	если (fvalue < 0) {
		signvalue = '-';
	} иначе {
		если (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} иначе {
			если (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#если 0
	если (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#если 0
	 если (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	если (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	если (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	do {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (целое) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} пока (intpart && (iplace < 311));
	если (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	если (fracpart)
	{
		do {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (целое) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} пока(fracpart && (fplace < 311));
		если (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	если (zpadlen < 0) zpadlen = 0;
	если (padlen < 0)
		padlen = 0;
	если (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	если ((flags & DP_F_ZERO) && (padlen > 0)) {
		если (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		пока (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	пока (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	если (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	пока (iplace > 0) {
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
	если (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		пока (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		пока (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	пока (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	вернуть 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#если !defined(HAVE_VSNPRINTF)
целое
vsnprintf (char *str, size_t count, const char *fmt, va_list args)
{
	вернуть dopr(str, count, fmt, args);
}
#endif

#если !defined(HAVE_SNPRINTF)
целое
snprintf(char *str, size_t count, SNPRINTF_CONST char *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, count, fmt, ap);
	va_end(ap);
	вернуть ret;
}
#endif
