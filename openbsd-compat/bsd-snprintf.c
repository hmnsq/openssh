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

#அந்தர்பாவ "includes.h"

#எனில் defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#எனில் !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long இரட்டை
#இல்லையெனில்
# define LDOUBLE இரட்டை
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#இல்லையெனில்
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
#define DP_F_இலக்கம்	(1 << 3)
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
	செய் { \
		எனில் (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			திரும்பு -1; \
		} \
		எனில் (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} போது (0)

நிலையான முழு dopr(எழுத்து *buffer, size_t maxlen, மாறிலி எழுத்து *format,
    va_list args_in);
நிலையான முழு fmtstr(எழுத்து *buffer, size_t *currlen, size_t maxlen,
    எழுத்து *மதிப்பு, முழு flags, முழு min, முழு max);
நிலையான முழு fmtint(எழுத்து *buffer, size_t *currlen, size_t maxlen,
    intmax_t மதிப்பு, முழு base, முழு min, முழு max, முழு flags);
நிலையான முழு fmtfp(எழுத்து *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, முழு min, முழு max, முழு flags);

நிலையான முழு
dopr(எழுத்து *buffer, size_t maxlen, மாறிலி எழுத்து *format, va_list args_in)
{
	எழுத்து ch;
	intmax_t மதிப்பு;
	LDOUBLE fvalue;
	எழுத்து *strvalue;
	முழு min;
	முழு max;
	முழு state;
	முழு flags;
	முழு cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	போது (state != DP_S_DONE) {
		எனில் (ch == '\0')
			state = DP_S_DONE;

		தேர்வு(state) {
		நிலை DP_S_DEFAULT:
			எனில் (ch == '%')
				state = DP_S_FLAGS;
			இல்லையெனில்
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			நிறுத்து;
		நிலை DP_S_FLAGS:
			தேர்வு (ch) {
			நிலை '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				நிறுத்து;
			நிலை '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				நிறுத்து;
			நிலை ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				நிறுத்து;
			நிலை '#':
				flags |= DP_F_இலக்கம்;
				ch = *format++;
				நிறுத்து;
			நிலை '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				நிறுத்து;
			இயல்பு:
				state = DP_S_MIN;
				நிறுத்து;
			}
			நிறுத்து;
		நிலை DP_S_MIN:
			எனில் (isdigit((unsigned எழுத்து)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} இல்லையெனில் எனில் (ch == '*') {
				min = va_arg (args, முழு);
				ch = *format++;
				state = DP_S_DOT;
			} இல்லையெனில் {
				state = DP_S_DOT;
			}
			நிறுத்து;
		நிலை DP_S_DOT:
			எனில் (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} இல்லையெனில் {
				state = DP_S_MOD;
			}
			நிறுத்து;
		நிலை DP_S_MAX:
			எனில் (isdigit((unsigned எழுத்து)ch)) {
				எனில் (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} இல்லையெனில் எனில் (ch == '*') {
				max = va_arg (args, முழு);
				ch = *format++;
				state = DP_S_MOD;
			} இல்லையெனில் {
				state = DP_S_MOD;
			}
			நிறுத்து;
		நிலை DP_S_MOD:
			தேர்வு (ch) {
			நிலை 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				நிறுத்து;
			நிலை 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				நிறுத்து;
			நிலை 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				எனில் (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				நிறுத்து;
			நிலை 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				நிறுத்து;
			நிலை 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				நிறுத்து;
			இயல்பு:
				நிறுத்து;
			}
			state = DP_S_CONV;
			நிறுத்து;
		நிலை DP_S_CONV:
			தேர்வு (ch) {
			நிலை 'd':
			நிலை 'i':
				எனில் (cflags == DP_C_SHORT)
					மதிப்பு = va_arg (args, முழு);
				இல்லையெனில் எனில் (cflags == DP_C_LONG)
					மதிப்பு = va_arg (args, long முழு);
				இல்லையெனில் எனில் (cflags == DP_C_LLONG)
					மதிப்பு = va_arg (args, LLONG);
				இல்லையெனில் எனில் (cflags == DP_C_SIZE)
					மதிப்பு = va_arg (args, ssize_t);
				இல்லையெனில் எனில் (cflags == DP_C_INTMAX)
					மதிப்பு = va_arg (args, intmax_t);
				இல்லையெனில்
					மதிப்பு = va_arg (args, முழு);
				எனில் (fmtint(buffer, &currlen, maxlen,
				    மதிப்பு, 10, min, max, flags) == -1)
					செல் fail;
				நிறுத்து;
			நிலை 'o':
				flags |= DP_F_UNSIGNED;
				எனில் (cflags == DP_C_SHORT)
					மதிப்பு = va_arg (args, unsigned முழு);
				இல்லையெனில் எனில் (cflags == DP_C_LONG)
					மதிப்பு = (long)va_arg (args, unsigned long முழு);
				இல்லையெனில் எனில் (cflags == DP_C_LLONG)
					மதிப்பு = (long)va_arg (args, unsigned LLONG);
				இல்லையெனில் எனில் (cflags == DP_C_SIZE)
					மதிப்பு = va_arg (args, size_t);
#ifdef notyet
				இல்லையெனில் எனில் (cflags == DP_C_INTMAX)
					மதிப்பு = va_arg (args, uintmax_t);
#endif
				இல்லையெனில்
					மதிப்பு = (long)va_arg (args, unsigned முழு);
				எனில் (fmtint(buffer, &currlen, maxlen, மதிப்பு,
				    8, min, max, flags) == -1)
					செல் fail;
				நிறுத்து;
			நிலை 'u':
				flags |= DP_F_UNSIGNED;
				எனில் (cflags == DP_C_SHORT)
					மதிப்பு = va_arg (args, unsigned முழு);
				இல்லையெனில் எனில் (cflags == DP_C_LONG)
					மதிப்பு = (long)va_arg (args, unsigned long முழு);
				இல்லையெனில் எனில் (cflags == DP_C_LLONG)
					மதிப்பு = (LLONG)va_arg (args, unsigned LLONG);
				இல்லையெனில் எனில் (cflags == DP_C_SIZE)
					மதிப்பு = va_arg (args, size_t);
#ifdef notyet
				இல்லையெனில் எனில் (cflags == DP_C_INTMAX)
					மதிப்பு = va_arg (args, uintmax_t);
#endif
				இல்லையெனில்
					மதிப்பு = (long)va_arg (args, unsigned முழு);
				எனில் (fmtint(buffer, &currlen, maxlen, மதிப்பு,
				    10, min, max, flags) == -1)
					செல் fail;
				நிறுத்து;
			நிலை 'X':
				flags |= DP_F_UP;
			நிலை 'x':
				flags |= DP_F_UNSIGNED;
				எனில் (cflags == DP_C_SHORT)
					மதிப்பு = va_arg (args, unsigned முழு);
				இல்லையெனில் எனில் (cflags == DP_C_LONG)
					மதிப்பு = (long)va_arg (args, unsigned long முழு);
				இல்லையெனில் எனில் (cflags == DP_C_LLONG)
					மதிப்பு = (LLONG)va_arg (args, unsigned LLONG);
				இல்லையெனில் எனில் (cflags == DP_C_SIZE)
					மதிப்பு = va_arg (args, size_t);
#ifdef notyet
				இல்லையெனில் எனில் (cflags == DP_C_INTMAX)
					மதிப்பு = va_arg (args, uintmax_t);
#endif
				இல்லையெனில்
					மதிப்பு = (long)va_arg (args, unsigned முழு);
				எனில் (fmtint(buffer, &currlen, maxlen, மதிப்பு,
				    16, min, max, flags) == -1)
					செல் fail;
				நிறுத்து;
			நிலை 'f':
				எனில் (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				இல்லையெனில்
					fvalue = va_arg (args, இரட்டை);
				எனில் (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					செல் fail;
				நிறுத்து;
			நிலை 'E':
				flags |= DP_F_UP;
			நிலை 'e':
				எனில் (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				இல்லையெனில்
					fvalue = va_arg (args, இரட்டை);
				எனில் (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					செல் fail;
				நிறுத்து;
			நிலை 'G':
				flags |= DP_F_UP;
			நிலை 'g':
				எனில் (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				இல்லையெனில்
					fvalue = va_arg (args, இரட்டை);
				எனில் (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					செல் fail;
				நிறுத்து;
			நிலை 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, முழு));
				நிறுத்து;
			நிலை 's':
				strvalue = va_arg (args, எழுத்து *);
				எனில் (!strvalue) strvalue = "(NULL)";
				எனில் (max == -1) {
					max = strlen(strvalue);
				}
				எனில் (min > 0 && max >= 0 && min > max) max = min;
				எனில் (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					செல் fail;
				நிறுத்து;
			நிலை 'p':
				strvalue = va_arg (args, வெறுமை *);
				எனில் (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					செல் fail;
				நிறுத்து;
#எனில் we_dont_want_this_in_openssh
			நிலை 'n':
				எனில் (cflags == DP_C_SHORT) {
					short முழு *இலக்கம்;
					இலக்கம் = va_arg (args, short முழு *);
					*இலக்கம் = currlen;
				} இல்லையெனில் எனில் (cflags == DP_C_LONG) {
					long முழு *இலக்கம்;
					இலக்கம் = va_arg (args, long முழு *);
					*இலக்கம் = (long முழு)currlen;
				} இல்லையெனில் எனில் (cflags == DP_C_LLONG) {
					LLONG *இலக்கம்;
					இலக்கம் = va_arg (args, LLONG *);
					*இலக்கம் = (LLONG)currlen;
				} இல்லையெனில் எனில் (cflags == DP_C_SIZE) {
					ssize_t *இலக்கம்;
					இலக்கம் = va_arg (args, ssize_t *);
					*இலக்கம் = (ssize_t)currlen;
				} இல்லையெனில் எனில் (cflags == DP_C_INTMAX) {
					intmax_t *இலக்கம்;
					இலக்கம் = va_arg (args, intmax_t *);
					*இலக்கம் = (intmax_t)currlen;
				} இல்லையெனில் {
					முழு *இலக்கம்;
					இலக்கம் = va_arg (args, முழு *);
					*இலக்கம் = currlen;
				}
				நிறுத்து;
#endif
			நிலை '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				நிறுத்து;
			இயல்பு:
				/* Unknown, skip */
				நிறுத்து;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			நிறுத்து;
		நிலை DP_S_DONE:
			நிறுத்து;
		இயல்பு:
			/* hmm? */
			நிறுத்து; /* some picky compilers need this */
		}
	}
	எனில் (maxlen != 0) {
		எனில் (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		இல்லையெனில் எனில் (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	திரும்பு currlen < INT_MAX ? (முழு)currlen : -1;
 fail:
	va_end(args);
	திரும்பு -1;
}

நிலையான முழு
fmtstr(எழுத்து *buffer, size_t *currlen, size_t maxlen,
    எழுத்து *மதிப்பு, முழு flags, முழு min, முழு max)
{
	முழு padlen, strln;     /* amount to pad */
	முழு cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, மதிப்பு);
#endif
	எனில் (மதிப்பு == 0) {
		மதிப்பு = "<NULL>";
	}

	க்கு (strln = 0; strln < max && மதிப்பு[strln]; ++strln); /* strlen */
	padlen = min - strln;
	எனில் (padlen < 0)
		padlen = 0;
	எனில் (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	போது ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	போது (*மதிப்பு && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *மதிப்பு);
		மதிப்பு++;
		++cnt;
	}
	போது ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	திரும்பு 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

நிலையான முழு
fmtint(எழுத்து *buffer, size_t *currlen, size_t maxlen,
    intmax_t மதிப்பு, முழு base, முழு min, முழு max, முழு flags)
{
	முழு signvalue = 0;
	unsigned LLONG uvalue;
	எழுத்து convert[20];
	முழு place = 0;
	முழு spadlen = 0; /* amount to space pad */
	முழு zpadlen = 0; /* amount to zero pad */
	முழு caps = 0;

	எனில் (max < 0)
		max = 0;

	uvalue = மதிப்பு;

	எனில்(!(flags & DP_F_UNSIGNED)) {
		எனில்( மதிப்பு < 0 ) {
			signvalue = '-';
			uvalue = -மதிப்பு;
		} இல்லையெனில் {
			எனில் (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			இல்லையெனில் எனில் (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	எனில் (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	செய் {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} போது(uvalue && (place < 20));
	எனில் (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	எனில் (zpadlen < 0) zpadlen = 0;
	எனில் (spadlen < 0) spadlen = 0;
	எனில் (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	எனில் (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	போது (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	எனில் (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	எனில் (zpadlen > 0) {
		போது (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	போது (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	போது (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	திரும்பு 0;
}

நிலையான LDOUBLE abs_val(LDOUBLE மதிப்பு)
{
	LDOUBLE result = மதிப்பு;

	எனில் (மதிப்பு < 0)
		result = -மதிப்பு;

	திரும்பு result;
}

நிலையான LDOUBLE POW10(முழு val)
{
	LDOUBLE result = 1;

	போது (val) {
		result *= 10;
		val--;
	}

	திரும்பு result;
}

நிலையான LLONG ROUND(LDOUBLE மதிப்பு)
{
	LLONG intpart;

	intpart = (LLONG)மதிப்பு;
	மதிப்பு = மதிப்பு - intpart;
	எனில் (மதிப்பு >= 0.5) intpart++;

	திரும்பு intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
நிலையான இரட்டை my_modf(இரட்டை x0, இரட்டை *iptr)
{
	முழு i;
	long l;
	இரட்டை x = x0;
	இரட்டை f = 1.0;

	க்கு (i=0;i<100;i++) {
		l = (long)x;
		எனில் (l <= (x+1) && l >= (x-1)) நிறுத்து;
		x *= 0.1;
		f *= 10.0;
	}

	எனில் (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		திரும்பு 0;
	}

	எனில் (i != 0) {
		இரட்டை i2;
		இரட்டை ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		திரும்பு ret;
	}

	(*iptr) = l;
	திரும்பு x - (*iptr);
}


நிலையான முழு
fmtfp (எழுத்து *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, முழு min, முழு max, முழு flags)
{
	முழு signvalue = 0;
	இரட்டை ufvalue;
	எழுத்து iconvert[311];
	எழுத்து fconvert[311];
	முழு iplace = 0;
	முழு fplace = 0;
	முழு padlen = 0; /* amount to pad */
	முழு zpadlen = 0;
#எனில் 0
	முழு caps = 0;
#endif
	முழு idx;
	இரட்டை intpart;
	இரட்டை fracpart;
	இரட்டை temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	எனில் (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	எனில் (fvalue < 0) {
		signvalue = '-';
	} இல்லையெனில் {
		எனில் (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} இல்லையெனில் {
			எனில் (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#எனில் 0
	எனில் (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#எனில் 0
	 எனில் (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	எனில் (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	எனில் (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	செய் {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (முழு) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} போது (intpart && (iplace < 311));
	எனில் (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	எனில் (fracpart)
	{
		செய் {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (முழு) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} போது(fracpart && (fplace < 311));
		எனில் (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	எனில் (zpadlen < 0) zpadlen = 0;
	எனில் (padlen < 0)
		padlen = 0;
	எனில் (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	எனில் ((flags & DP_F_ZERO) && (padlen > 0)) {
		எனில் (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		போது (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	போது (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	எனில் (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	போது (iplace > 0) {
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
	எனில் (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		போது (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		போது (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	போது (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	திரும்பு 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#எனில் !defined(HAVE_VSNPRINTF)
முழு
vsnprintf (எழுத்து *str, size_t மொத்தம், மாறிலி எழுத்து *fmt, va_list args)
{
	திரும்பு dopr(str, மொத்தம், fmt, args);
}
#endif

#எனில் !defined(HAVE_SNPRINTF)
முழு
snprintf(எழுத்து *str, size_t மொத்தம், SNPRINTF_CONST எழுத்து *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, மொத்தம், fmt, ap);
	va_end(ap);
	திரும்பு ret;
}
#endif
