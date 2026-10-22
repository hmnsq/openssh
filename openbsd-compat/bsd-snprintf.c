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

#અન્તર્ભાવ "includes.h"

#જો defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#જો !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long દ્વિગુણ
#નહીંતર
# define LDOUBLE દ્વિગુણ
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#નહીંતર
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
#define DP_F_અંક	(1 << 3)
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
	કરો { \
		જો (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			પાછા -1; \
		} \
		જો (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} જ્યારે (0)

સ્થિર પૂર્ણાંક dopr(અક્ષર *buffer, size_t maxlen, અચલ અક્ષર *format,
    va_list args_in);
સ્થિર પૂર્ણાંક fmtstr(અક્ષર *buffer, size_t *currlen, size_t maxlen,
    અક્ષર *કિંમત, પૂર્ણાંક flags, પૂર્ણાંક min, પૂર્ણાંક max);
સ્થિર પૂર્ણાંક fmtint(અક્ષર *buffer, size_t *currlen, size_t maxlen,
    intmax_t કિંમત, પૂર્ણાંક base, પૂર્ણાંક min, પૂર્ણાંક max, પૂર્ણાંક flags);
સ્થિર પૂર્ણાંક fmtfp(અક્ષર *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, પૂર્ણાંક min, પૂર્ણાંક max, પૂર્ણાંક flags);

સ્થિર પૂર્ણાંક
dopr(અક્ષર *buffer, size_t maxlen, અચલ અક્ષર *format, va_list args_in)
{
	અક્ષર ch;
	intmax_t કિંમત;
	LDOUBLE fvalue;
	અક્ષર *strvalue;
	પૂર્ણાંક min;
	પૂર્ણાંક max;
	પૂર્ણાંક state;
	પૂર્ણાંક flags;
	પૂર્ણાંક cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	જ્યારે (state != DP_S_DONE) {
		જો (ch == '\0')
			state = DP_S_DONE;

		પસંદગી(state) {
		સ્થિતિ DP_S_DEFAULT:
			જો (ch == '%')
				state = DP_S_FLAGS;
			નહીંતર
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			તોડો;
		સ્થિતિ DP_S_FLAGS:
			પસંદગી (ch) {
			સ્થિતિ '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				તોડો;
			સ્થિતિ '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				તોડો;
			સ્થિતિ ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				તોડો;
			સ્થિતિ '#':
				flags |= DP_F_અંક;
				ch = *format++;
				તોડો;
			સ્થિતિ '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				તોડો;
			મૂળભૂત:
				state = DP_S_MIN;
				તોડો;
			}
			તોડો;
		સ્થિતિ DP_S_MIN:
			જો (isdigit((unsigned અક્ષર)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} નહીંતર જો (ch == '*') {
				min = va_arg (args, પૂર્ણાંક);
				ch = *format++;
				state = DP_S_DOT;
			} નહીંતર {
				state = DP_S_DOT;
			}
			તોડો;
		સ્થિતિ DP_S_DOT:
			જો (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} નહીંતર {
				state = DP_S_MOD;
			}
			તોડો;
		સ્થિતિ DP_S_MAX:
			જો (isdigit((unsigned અક્ષર)ch)) {
				જો (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} નહીંતર જો (ch == '*') {
				max = va_arg (args, પૂર્ણાંક);
				ch = *format++;
				state = DP_S_MOD;
			} નહીંતર {
				state = DP_S_MOD;
			}
			તોડો;
		સ્થિતિ DP_S_MOD:
			પસંદગી (ch) {
			સ્થિતિ 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				તોડો;
			સ્થિતિ 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				તોડો;
			સ્થિતિ 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				જો (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				તોડો;
			સ્થિતિ 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				તોડો;
			સ્થિતિ 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				તોડો;
			મૂળભૂત:
				તોડો;
			}
			state = DP_S_CONV;
			તોડો;
		સ્થિતિ DP_S_CONV:
			પસંદગી (ch) {
			સ્થિતિ 'd':
			સ્થિતિ 'i':
				જો (cflags == DP_C_SHORT)
					કિંમત = va_arg (args, પૂર્ણાંક);
				નહીંતર જો (cflags == DP_C_LONG)
					કિંમત = va_arg (args, long પૂર્ણાંક);
				નહીંતર જો (cflags == DP_C_LLONG)
					કિંમત = va_arg (args, LLONG);
				નહીંતર જો (cflags == DP_C_SIZE)
					કિંમત = va_arg (args, ssize_t);
				નહીંતર જો (cflags == DP_C_INTMAX)
					કિંમત = va_arg (args, intmax_t);
				નહીંતર
					કિંમત = va_arg (args, પૂર્ણાંક);
				જો (fmtint(buffer, &currlen, maxlen,
				    કિંમત, 10, min, max, flags) == -1)
					જાઓ fail;
				તોડો;
			સ્થિતિ 'o':
				flags |= DP_F_UNSIGNED;
				જો (cflags == DP_C_SHORT)
					કિંમત = va_arg (args, unsigned પૂર્ણાંક);
				નહીંતર જો (cflags == DP_C_LONG)
					કિંમત = (long)va_arg (args, unsigned long પૂર્ણાંક);
				નહીંતર જો (cflags == DP_C_LLONG)
					કિંમત = (long)va_arg (args, unsigned LLONG);
				નહીંતર જો (cflags == DP_C_SIZE)
					કિંમત = va_arg (args, size_t);
#ifdef notyet
				નહીંતર જો (cflags == DP_C_INTMAX)
					કિંમત = va_arg (args, uintmax_t);
#endif
				નહીંતર
					કિંમત = (long)va_arg (args, unsigned પૂર્ણાંક);
				જો (fmtint(buffer, &currlen, maxlen, કિંમત,
				    8, min, max, flags) == -1)
					જાઓ fail;
				તોડો;
			સ્થિતિ 'u':
				flags |= DP_F_UNSIGNED;
				જો (cflags == DP_C_SHORT)
					કિંમત = va_arg (args, unsigned પૂર્ણાંક);
				નહીંતર જો (cflags == DP_C_LONG)
					કિંમત = (long)va_arg (args, unsigned long પૂર્ણાંક);
				નહીંતર જો (cflags == DP_C_LLONG)
					કિંમત = (LLONG)va_arg (args, unsigned LLONG);
				નહીંતર જો (cflags == DP_C_SIZE)
					કિંમત = va_arg (args, size_t);
#ifdef notyet
				નહીંતર જો (cflags == DP_C_INTMAX)
					કિંમત = va_arg (args, uintmax_t);
#endif
				નહીંતર
					કિંમત = (long)va_arg (args, unsigned પૂર્ણાંક);
				જો (fmtint(buffer, &currlen, maxlen, કિંમત,
				    10, min, max, flags) == -1)
					જાઓ fail;
				તોડો;
			સ્થિતિ 'X':
				flags |= DP_F_UP;
			સ્થિતિ 'x':
				flags |= DP_F_UNSIGNED;
				જો (cflags == DP_C_SHORT)
					કિંમત = va_arg (args, unsigned પૂર્ણાંક);
				નહીંતર જો (cflags == DP_C_LONG)
					કિંમત = (long)va_arg (args, unsigned long પૂર્ણાંક);
				નહીંતર જો (cflags == DP_C_LLONG)
					કિંમત = (LLONG)va_arg (args, unsigned LLONG);
				નહીંતર જો (cflags == DP_C_SIZE)
					કિંમત = va_arg (args, size_t);
#ifdef notyet
				નહીંતર જો (cflags == DP_C_INTMAX)
					કિંમત = va_arg (args, uintmax_t);
#endif
				નહીંતર
					કિંમત = (long)va_arg (args, unsigned પૂર્ણાંક);
				જો (fmtint(buffer, &currlen, maxlen, કિંમત,
				    16, min, max, flags) == -1)
					જાઓ fail;
				તોડો;
			સ્થિતિ 'f':
				જો (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				નહીંતર
					fvalue = va_arg (args, દ્વિગુણ);
				જો (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					જાઓ fail;
				તોડો;
			સ્થિતિ 'E':
				flags |= DP_F_UP;
			સ્થિતિ 'e':
				જો (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				નહીંતર
					fvalue = va_arg (args, દ્વિગુણ);
				જો (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					જાઓ fail;
				તોડો;
			સ્થિતિ 'G':
				flags |= DP_F_UP;
			સ્થિતિ 'g':
				જો (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				નહીંતર
					fvalue = va_arg (args, દ્વિગુણ);
				જો (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					જાઓ fail;
				તોડો;
			સ્થિતિ 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, પૂર્ણાંક));
				તોડો;
			સ્થિતિ 's':
				strvalue = va_arg (args, અક્ષર *);
				જો (!strvalue) strvalue = "(NULL)";
				જો (max == -1) {
					max = strlen(strvalue);
				}
				જો (min > 0 && max >= 0 && min > max) max = min;
				જો (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					જાઓ fail;
				તોડો;
			સ્થિતિ 'p':
				strvalue = va_arg (args, શૂન્ય *);
				જો (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					જાઓ fail;
				તોડો;
#જો we_dont_want_this_in_openssh
			સ્થિતિ 'n':
				જો (cflags == DP_C_SHORT) {
					short પૂર્ણાંક *અંક;
					અંક = va_arg (args, short પૂર્ણાંક *);
					*અંક = currlen;
				} નહીંતર જો (cflags == DP_C_LONG) {
					long પૂર્ણાંક *અંક;
					અંક = va_arg (args, long પૂર્ણાંક *);
					*અંક = (long પૂર્ણાંક)currlen;
				} નહીંતર જો (cflags == DP_C_LLONG) {
					LLONG *અંક;
					અંક = va_arg (args, LLONG *);
					*અંક = (LLONG)currlen;
				} નહીંતર જો (cflags == DP_C_SIZE) {
					ssize_t *અંક;
					અંક = va_arg (args, ssize_t *);
					*અંક = (ssize_t)currlen;
				} નહીંતર જો (cflags == DP_C_INTMAX) {
					intmax_t *અંક;
					અંક = va_arg (args, intmax_t *);
					*અંક = (intmax_t)currlen;
				} નહીંતર {
					પૂર્ણાંક *અંક;
					અંક = va_arg (args, પૂર્ણાંક *);
					*અંક = currlen;
				}
				તોડો;
#endif
			સ્થિતિ '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				તોડો;
			મૂળભૂત:
				/* Unknown, skip */
				તોડો;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			તોડો;
		સ્થિતિ DP_S_DONE:
			તોડો;
		મૂળભૂત:
			/* hmm? */
			તોડો; /* some picky compilers need this */
		}
	}
	જો (maxlen != 0) {
		જો (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		નહીંતર જો (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	પાછા currlen < INT_MAX ? (પૂર્ણાંક)currlen : -1;
 fail:
	va_end(args);
	પાછા -1;
}

સ્થિર પૂર્ણાંક
fmtstr(અક્ષર *buffer, size_t *currlen, size_t maxlen,
    અક્ષર *કિંમત, પૂર્ણાંક flags, પૂર્ણાંક min, પૂર્ણાંક max)
{
	પૂર્ણાંક padlen, strln;     /* amount to pad */
	પૂર્ણાંક cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, કિંમત);
#endif
	જો (કિંમત == 0) {
		કિંમત = "<NULL>";
	}

	માટે (strln = 0; strln < max && કિંમત[strln]; ++strln); /* strlen */
	padlen = min - strln;
	જો (padlen < 0)
		padlen = 0;
	જો (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	જ્યારે ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	જ્યારે (*કિંમત && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *કિંમત);
		કિંમત++;
		++cnt;
	}
	જ્યારે ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	પાછા 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

સ્થિર પૂર્ણાંક
fmtint(અક્ષર *buffer, size_t *currlen, size_t maxlen,
    intmax_t કિંમત, પૂર્ણાંક base, પૂર્ણાંક min, પૂર્ણાંક max, પૂર્ણાંક flags)
{
	પૂર્ણાંક signvalue = 0;
	unsigned LLONG uvalue;
	અક્ષર convert[20];
	પૂર્ણાંક place = 0;
	પૂર્ણાંક spadlen = 0; /* amount to space pad */
	પૂર્ણાંક zpadlen = 0; /* amount to zero pad */
	પૂર્ણાંક caps = 0;

	જો (max < 0)
		max = 0;

	uvalue = કિંમત;

	જો(!(flags & DP_F_UNSIGNED)) {
		જો( કિંમત < 0 ) {
			signvalue = '-';
			uvalue = -કિંમત;
		} નહીંતર {
			જો (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			નહીંતર જો (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	જો (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	કરો {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} જ્યારે(uvalue && (place < 20));
	જો (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	જો (zpadlen < 0) zpadlen = 0;
	જો (spadlen < 0) spadlen = 0;
	જો (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	જો (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	જ્યારે (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	જો (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	જો (zpadlen > 0) {
		જ્યારે (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	જ્યારે (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	જ્યારે (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	પાછા 0;
}

સ્થિર LDOUBLE abs_val(LDOUBLE કિંમત)
{
	LDOUBLE result = કિંમત;

	જો (કિંમત < 0)
		result = -કિંમત;

	પાછા result;
}

સ્થિર LDOUBLE POW10(પૂર્ણાંક val)
{
	LDOUBLE result = 1;

	જ્યારે (val) {
		result *= 10;
		val--;
	}

	પાછા result;
}

સ્થિર LLONG ROUND(LDOUBLE કિંમત)
{
	LLONG intpart;

	intpart = (LLONG)કિંમત;
	કિંમત = કિંમત - intpart;
	જો (કિંમત >= 0.5) intpart++;

	પાછા intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
સ્થિર દ્વિગુણ my_modf(દ્વિગુણ x0, દ્વિગુણ *iptr)
{
	પૂર્ણાંક i;
	long l;
	દ્વિગુણ x = x0;
	દ્વિગુણ f = 1.0;

	માટે (i=0;i<100;i++) {
		l = (long)x;
		જો (l <= (x+1) && l >= (x-1)) તોડો;
		x *= 0.1;
		f *= 10.0;
	}

	જો (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		પાછા 0;
	}

	જો (i != 0) {
		દ્વિગુણ i2;
		દ્વિગુણ ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		પાછા ret;
	}

	(*iptr) = l;
	પાછા x - (*iptr);
}


સ્થિર પૂર્ણાંક
fmtfp (અક્ષર *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, પૂર્ણાંક min, પૂર્ણાંક max, પૂર્ણાંક flags)
{
	પૂર્ણાંક signvalue = 0;
	દ્વિગુણ ufvalue;
	અક્ષર iconvert[311];
	અક્ષર fconvert[311];
	પૂર્ણાંક iplace = 0;
	પૂર્ણાંક fplace = 0;
	પૂર્ણાંક padlen = 0; /* amount to pad */
	પૂર્ણાંક zpadlen = 0;
#જો 0
	પૂર્ણાંક caps = 0;
#endif
	પૂર્ણાંક idx;
	દ્વિગુણ intpart;
	દ્વિગુણ fracpart;
	દ્વિગુણ temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	જો (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	જો (fvalue < 0) {
		signvalue = '-';
	} નહીંતર {
		જો (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} નહીંતર {
			જો (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#જો 0
	જો (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#જો 0
	 જો (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	જો (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	જો (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	કરો {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (પૂર્ણાંક) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} જ્યારે (intpart && (iplace < 311));
	જો (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	જો (fracpart)
	{
		કરો {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (પૂર્ણાંક) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} જ્યારે(fracpart && (fplace < 311));
		જો (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	જો (zpadlen < 0) zpadlen = 0;
	જો (padlen < 0)
		padlen = 0;
	જો (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	જો ((flags & DP_F_ZERO) && (padlen > 0)) {
		જો (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		જ્યારે (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	જ્યારે (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	જો (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	જ્યારે (iplace > 0) {
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
	જો (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		જ્યારે (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		જ્યારે (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	જ્યારે (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	પાછા 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#જો !defined(HAVE_VSNPRINTF)
પૂર્ણાંક
vsnprintf (અક્ષર *str, size_t ગણતરી, અચલ અક્ષર *fmt, va_list args)
{
	પાછા dopr(str, ગણતરી, fmt, args);
}
#endif

#જો !defined(HAVE_SNPRINTF)
પૂર્ણાંક
snprintf(અક્ષર *str, size_t ગણતરી, SNPRINTF_CONST અક્ષર *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, ગણતરી, fmt, ap);
	va_end(ap);
	પાછા ret;
}
#endif
