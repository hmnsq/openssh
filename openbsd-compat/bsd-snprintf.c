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
#endif

#اگر !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#شامل <ctype.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <limits.h>
#شامل <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long دوگانه
#وگرنه
# define LDOUBLE دوگانه
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#وگرنه
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
#define DP_F_رقم	(1 << 3)
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
	انجامبده { \
		اگر (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			بازگشت -1; \
		} \
		اگر (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} وقتی (0)

ایستا صحیح dopr(نویسه *buffer, size_t maxlen, ثابت نویسه *format,
    va_list args_in);
ایستا صحیح fmtstr(نویسه *buffer, size_t *currlen, size_t maxlen,
    نویسه *مقدار, صحیح flags, صحیح min, صحیح max);
ایستا صحیح fmtint(نویسه *buffer, size_t *currlen, size_t maxlen,
    intmax_t مقدار, صحیح base, صحیح min, صحیح max, صحیح flags);
ایستا صحیح fmtfp(نویسه *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, صحیح min, صحیح max, صحیح flags);

ایستا صحیح
dopr(نویسه *buffer, size_t maxlen, ثابت نویسه *format, va_list args_in)
{
	نویسه ch;
	intmax_t مقدار;
	LDOUBLE fvalue;
	نویسه *strvalue;
	صحیح min;
	صحیح max;
	صحیح state;
	صحیح flags;
	صحیح cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	وقتی (state != DP_S_DONE) {
		اگر (ch == '\0')
			state = DP_S_DONE;

		انتخاب(state) {
		حالت DP_S_DEFAULT:
			اگر (ch == '%')
				state = DP_S_FLAGS;
			وگرنه
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			بشکن;
		حالت DP_S_FLAGS:
			انتخاب (ch) {
			حالت '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				بشکن;
			حالت '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				بشکن;
			حالت ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				بشکن;
			حالت '#':
				flags |= DP_F_رقم;
				ch = *format++;
				بشکن;
			حالت '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				بشکن;
			پیشفرض:
				state = DP_S_MIN;
				بشکن;
			}
			بشکن;
		حالت DP_S_MIN:
			اگر (isdigit((unsigned نویسه)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} وگرنه اگر (ch == '*') {
				min = va_arg (args, صحیح);
				ch = *format++;
				state = DP_S_DOT;
			} وگرنه {
				state = DP_S_DOT;
			}
			بشکن;
		حالت DP_S_DOT:
			اگر (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} وگرنه {
				state = DP_S_MOD;
			}
			بشکن;
		حالت DP_S_MAX:
			اگر (isdigit((unsigned نویسه)ch)) {
				اگر (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} وگرنه اگر (ch == '*') {
				max = va_arg (args, صحیح);
				ch = *format++;
				state = DP_S_MOD;
			} وگرنه {
				state = DP_S_MOD;
			}
			بشکن;
		حالت DP_S_MOD:
			انتخاب (ch) {
			حالت 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				بشکن;
			حالت 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				بشکن;
			حالت 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				اگر (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				بشکن;
			حالت 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				بشکن;
			حالت 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				بشکن;
			پیشفرض:
				بشکن;
			}
			state = DP_S_CONV;
			بشکن;
		حالت DP_S_CONV:
			انتخاب (ch) {
			حالت 'd':
			حالت 'i':
				اگر (cflags == DP_C_SHORT)
					مقدار = va_arg (args, صحیح);
				وگرنه اگر (cflags == DP_C_LONG)
					مقدار = va_arg (args, long صحیح);
				وگرنه اگر (cflags == DP_C_LLONG)
					مقدار = va_arg (args, LLONG);
				وگرنه اگر (cflags == DP_C_SIZE)
					مقدار = va_arg (args, ssize_t);
				وگرنه اگر (cflags == DP_C_INTMAX)
					مقدار = va_arg (args, intmax_t);
				وگرنه
					مقدار = va_arg (args, صحیح);
				اگر (fmtint(buffer, &currlen, maxlen,
				    مقدار, 10, min, max, flags) == -1)
					برو fail;
				بشکن;
			حالت 'o':
				flags |= DP_F_UNSIGNED;
				اگر (cflags == DP_C_SHORT)
					مقدار = va_arg (args, unsigned صحیح);
				وگرنه اگر (cflags == DP_C_LONG)
					مقدار = (long)va_arg (args, unsigned long صحیح);
				وگرنه اگر (cflags == DP_C_LLONG)
					مقدار = (long)va_arg (args, unsigned LLONG);
				وگرنه اگر (cflags == DP_C_SIZE)
					مقدار = va_arg (args, size_t);
#ifdef notyet
				وگرنه اگر (cflags == DP_C_INTMAX)
					مقدار = va_arg (args, uintmax_t);
#endif
				وگرنه
					مقدار = (long)va_arg (args, unsigned صحیح);
				اگر (fmtint(buffer, &currlen, maxlen, مقدار,
				    8, min, max, flags) == -1)
					برو fail;
				بشکن;
			حالت 'u':
				flags |= DP_F_UNSIGNED;
				اگر (cflags == DP_C_SHORT)
					مقدار = va_arg (args, unsigned صحیح);
				وگرنه اگر (cflags == DP_C_LONG)
					مقدار = (long)va_arg (args, unsigned long صحیح);
				وگرنه اگر (cflags == DP_C_LLONG)
					مقدار = (LLONG)va_arg (args, unsigned LLONG);
				وگرنه اگر (cflags == DP_C_SIZE)
					مقدار = va_arg (args, size_t);
#ifdef notyet
				وگرنه اگر (cflags == DP_C_INTMAX)
					مقدار = va_arg (args, uintmax_t);
#endif
				وگرنه
					مقدار = (long)va_arg (args, unsigned صحیح);
				اگر (fmtint(buffer, &currlen, maxlen, مقدار,
				    10, min, max, flags) == -1)
					برو fail;
				بشکن;
			حالت 'X':
				flags |= DP_F_UP;
			حالت 'x':
				flags |= DP_F_UNSIGNED;
				اگر (cflags == DP_C_SHORT)
					مقدار = va_arg (args, unsigned صحیح);
				وگرنه اگر (cflags == DP_C_LONG)
					مقدار = (long)va_arg (args, unsigned long صحیح);
				وگرنه اگر (cflags == DP_C_LLONG)
					مقدار = (LLONG)va_arg (args, unsigned LLONG);
				وگرنه اگر (cflags == DP_C_SIZE)
					مقدار = va_arg (args, size_t);
#ifdef notyet
				وگرنه اگر (cflags == DP_C_INTMAX)
					مقدار = va_arg (args, uintmax_t);
#endif
				وگرنه
					مقدار = (long)va_arg (args, unsigned صحیح);
				اگر (fmtint(buffer, &currlen, maxlen, مقدار,
				    16, min, max, flags) == -1)
					برو fail;
				بشکن;
			حالت 'f':
				اگر (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				وگرنه
					fvalue = va_arg (args, دوگانه);
				اگر (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					برو fail;
				بشکن;
			حالت 'E':
				flags |= DP_F_UP;
			حالت 'e':
				اگر (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				وگرنه
					fvalue = va_arg (args, دوگانه);
				اگر (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					برو fail;
				بشکن;
			حالت 'G':
				flags |= DP_F_UP;
			حالت 'g':
				اگر (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				وگرنه
					fvalue = va_arg (args, دوگانه);
				اگر (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					برو fail;
				بشکن;
			حالت 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, صحیح));
				بشکن;
			حالت 's':
				strvalue = va_arg (args, نویسه *);
				اگر (!strvalue) strvalue = "(NULL)";
				اگر (max == -1) {
					max = strlen(strvalue);
				}
				اگر (min > 0 && max >= 0 && min > max) max = min;
				اگر (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					برو fail;
				بشکن;
			حالت 'p':
				strvalue = va_arg (args, تهی *);
				اگر (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					برو fail;
				بشکن;
#اگر we_dont_want_this_in_openssh
			حالت 'n':
				اگر (cflags == DP_C_SHORT) {
					short صحیح *رقم;
					رقم = va_arg (args, short صحیح *);
					*رقم = currlen;
				} وگرنه اگر (cflags == DP_C_LONG) {
					long صحیح *رقم;
					رقم = va_arg (args, long صحیح *);
					*رقم = (long صحیح)currlen;
				} وگرنه اگر (cflags == DP_C_LLONG) {
					LLONG *رقم;
					رقم = va_arg (args, LLONG *);
					*رقم = (LLONG)currlen;
				} وگرنه اگر (cflags == DP_C_SIZE) {
					ssize_t *رقم;
					رقم = va_arg (args, ssize_t *);
					*رقم = (ssize_t)currlen;
				} وگرنه اگر (cflags == DP_C_INTMAX) {
					intmax_t *رقم;
					رقم = va_arg (args, intmax_t *);
					*رقم = (intmax_t)currlen;
				} وگرنه {
					صحیح *رقم;
					رقم = va_arg (args, صحیح *);
					*رقم = currlen;
				}
				بشکن;
#endif
			حالت '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				بشکن;
			پیشفرض:
				/* Unknown, skip */
				بشکن;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			بشکن;
		حالت DP_S_DONE:
			بشکن;
		پیشفرض:
			/* hmm? */
			بشکن; /* some picky compilers need this */
		}
	}
	اگر (maxlen != 0) {
		اگر (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		وگرنه اگر (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	بازگشت currlen < INT_MAX ? (صحیح)currlen : -1;
 fail:
	va_end(args);
	بازگشت -1;
}

ایستا صحیح
fmtstr(نویسه *buffer, size_t *currlen, size_t maxlen,
    نویسه *مقدار, صحیح flags, صحیح min, صحیح max)
{
	صحیح padlen, strln;     /* amount to pad */
	صحیح cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, مقدار);
#endif
	اگر (مقدار == 0) {
		مقدار = "<NULL>";
	}

	برای (strln = 0; strln < max && مقدار[strln]; ++strln); /* strlen */
	padlen = min - strln;
	اگر (padlen < 0)
		padlen = 0;
	اگر (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	وقتی ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	وقتی (*مقدار && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *مقدار);
		مقدار++;
		++cnt;
	}
	وقتی ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	بازگشت 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

ایستا صحیح
fmtint(نویسه *buffer, size_t *currlen, size_t maxlen,
    intmax_t مقدار, صحیح base, صحیح min, صحیح max, صحیح flags)
{
	صحیح signvalue = 0;
	unsigned LLONG uvalue;
	نویسه convert[20];
	صحیح place = 0;
	صحیح spadlen = 0; /* amount to space pad */
	صحیح zpadlen = 0; /* amount to zero pad */
	صحیح caps = 0;

	اگر (max < 0)
		max = 0;

	uvalue = مقدار;

	اگر(!(flags & DP_F_UNSIGNED)) {
		اگر( مقدار < 0 ) {
			signvalue = '-';
			uvalue = -مقدار;
		} وگرنه {
			اگر (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			وگرنه اگر (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	اگر (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	انجامبده {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} وقتی(uvalue && (place < 20));
	اگر (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	اگر (zpadlen < 0) zpadlen = 0;
	اگر (spadlen < 0) spadlen = 0;
	اگر (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	اگر (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	وقتی (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	اگر (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	اگر (zpadlen > 0) {
		وقتی (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	وقتی (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	وقتی (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	بازگشت 0;
}

ایستا LDOUBLE abs_val(LDOUBLE مقدار)
{
	LDOUBLE result = مقدار;

	اگر (مقدار < 0)
		result = -مقدار;

	بازگشت result;
}

ایستا LDOUBLE POW10(صحیح val)
{
	LDOUBLE result = 1;

	وقتی (val) {
		result *= 10;
		val--;
	}

	بازگشت result;
}

ایستا LLONG ROUND(LDOUBLE مقدار)
{
	LLONG intpart;

	intpart = (LLONG)مقدار;
	مقدار = مقدار - intpart;
	اگر (مقدار >= 0.5) intpart++;

	بازگشت intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
ایستا دوگانه my_modf(دوگانه x0, دوگانه *iptr)
{
	صحیح i;
	long l;
	دوگانه x = x0;
	دوگانه f = 1.0;

	برای (i=0;i<100;i++) {
		l = (long)x;
		اگر (l <= (x+1) && l >= (x-1)) بشکن;
		x *= 0.1;
		f *= 10.0;
	}

	اگر (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		بازگشت 0;
	}

	اگر (i != 0) {
		دوگانه i2;
		دوگانه ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		بازگشت ret;
	}

	(*iptr) = l;
	بازگشت x - (*iptr);
}


ایستا صحیح
fmtfp (نویسه *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, صحیح min, صحیح max, صحیح flags)
{
	صحیح signvalue = 0;
	دوگانه ufvalue;
	نویسه iconvert[311];
	نویسه fconvert[311];
	صحیح iplace = 0;
	صحیح fplace = 0;
	صحیح padlen = 0; /* amount to pad */
	صحیح zpadlen = 0;
#اگر 0
	صحیح caps = 0;
#endif
	صحیح idx;
	دوگانه intpart;
	دوگانه fracpart;
	دوگانه temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	اگر (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	اگر (fvalue < 0) {
		signvalue = '-';
	} وگرنه {
		اگر (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} وگرنه {
			اگر (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#اگر 0
	اگر (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#اگر 0
	 اگر (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	اگر (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	اگر (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	انجامبده {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (صحیح) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} وقتی (intpart && (iplace < 311));
	اگر (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	اگر (fracpart)
	{
		انجامبده {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (صحیح) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} وقتی(fracpart && (fplace < 311));
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
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		وقتی (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	وقتی (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	اگر (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	وقتی (iplace > 0) {
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
	اگر (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		وقتی (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		وقتی (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	وقتی (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	بازگشت 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#اگر !defined(HAVE_VSNPRINTF)
صحیح
vsnprintf (نویسه *str, size_t شمار, ثابت نویسه *fmt, va_list args)
{
	بازگشت dopr(str, شمار, fmt, args);
}
#endif

#اگر !defined(HAVE_SNPRINTF)
صحیح
snprintf(نویسه *str, size_t شمار, SNPRINTF_CONST نویسه *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, شمار, fmt, ap);
	va_end(ap);
	بازگشت ret;
}
#endif
