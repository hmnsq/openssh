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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#ଯଦି !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long ଦ୍ୱିଗୁଣ
#ଅନ୍ୟଥା
# define LDOUBLE ଦ୍ୱିଗୁଣ
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#ଅନ୍ୟଥା
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
#define DP_F_ଅଙ୍କ	(1 << 3)
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
	କର { \
		ଯଦି (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			ଫେରନ୍ତୁ -1; \
		} \
		ଯଦି (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} ଯେତେବେଳେ (0)

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା dopr(ଅକ୍ଷର *buffer, size_t maxlen, ଅଚଳ ଅକ୍ଷର *format,
    va_list args_in);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା fmtstr(ଅକ୍ଷର *buffer, size_t *currlen, size_t maxlen,
    ଅକ୍ଷର *ମୂଲ୍ୟ, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags, ପୂର୍ଣ୍ଣସଂଖ୍ୟା min, ପୂର୍ଣ୍ଣସଂଖ୍ୟା max);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା fmtint(ଅକ୍ଷର *buffer, size_t *currlen, size_t maxlen,
    intmax_t ମୂଲ୍ୟ, ପୂର୍ଣ୍ଣସଂଖ୍ୟା base, ପୂର୍ଣ୍ଣସଂଖ୍ୟା min, ପୂର୍ଣ୍ଣସଂଖ୍ୟା max, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା fmtfp(ଅକ୍ଷର *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, ପୂର୍ଣ୍ଣସଂଖ୍ୟା min, ପୂର୍ଣ୍ଣସଂଖ୍ୟା max, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags);

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
dopr(ଅକ୍ଷର *buffer, size_t maxlen, ଅଚଳ ଅକ୍ଷର *format, va_list args_in)
{
	ଅକ୍ଷର ch;
	intmax_t ମୂଲ୍ୟ;
	LDOUBLE fvalue;
	ଅକ୍ଷର *strvalue;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା min;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା max;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା state;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	ଯେତେବେଳେ (state != DP_S_DONE) {
		ଯଦି (ch == '\0')
			state = DP_S_DONE;

		ବାଛ(state) {
		ସ୍ଥିତି DP_S_DEFAULT:
			ଯଦି (ch == '%')
				state = DP_S_FLAGS;
			ଅନ୍ୟଥା
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି DP_S_FLAGS:
			ବାଛ (ch) {
			ସ୍ଥିତି '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି '#':
				flags |= DP_F_ଅଙ୍କ;
				ch = *format++;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				ଭାଙ୍ଗ;
			ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
				state = DP_S_MIN;
				ଭାଙ୍ଗ;
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି DP_S_MIN:
			ଯଦି (isdigit((unsigned ଅକ୍ଷର)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} ଅନ୍ୟଥା ଯଦି (ch == '*') {
				min = va_arg (args, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ch = *format++;
				state = DP_S_DOT;
			} ଅନ୍ୟଥା {
				state = DP_S_DOT;
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି DP_S_DOT:
			ଯଦି (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} ଅନ୍ୟଥା {
				state = DP_S_MOD;
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି DP_S_MAX:
			ଯଦି (isdigit((unsigned ଅକ୍ଷର)ch)) {
				ଯଦି (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} ଅନ୍ୟଥା ଯଦି (ch == '*') {
				max = va_arg (args, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ch = *format++;
				state = DP_S_MOD;
			} ଅନ୍ୟଥା {
				state = DP_S_MOD;
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି DP_S_MOD:
			ବାଛ (ch) {
			ସ୍ଥିତି 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				ଯଦି (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				ଭାଙ୍ଗ;
			ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
				ଭାଙ୍ଗ;
			}
			state = DP_S_CONV;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି DP_S_CONV:
			ବାଛ (ch) {
			ସ୍ଥିତି 'd':
			ସ୍ଥିତି 'i':
				ଯଦି (cflags == DP_C_SHORT)
					ମୂଲ୍ୟ = va_arg (args, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_LONG)
					ମୂଲ୍ୟ = va_arg (args, long ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_LLONG)
					ମୂଲ୍ୟ = va_arg (args, LLONG);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_SIZE)
					ମୂଲ୍ୟ = va_arg (args, ssize_t);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_INTMAX)
					ମୂଲ୍ୟ = va_arg (args, intmax_t);
				ଅନ୍ୟଥା
					ମୂଲ୍ୟ = va_arg (args, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଯଦି (fmtint(buffer, &currlen, maxlen,
				    ମୂଲ୍ୟ, 10, min, max, flags) == -1)
					ଯାଅ fail;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'o':
				flags |= DP_F_UNSIGNED;
				ଯଦି (cflags == DP_C_SHORT)
					ମୂଲ୍ୟ = va_arg (args, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_LONG)
					ମୂଲ୍ୟ = (long)va_arg (args, unsigned long ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_LLONG)
					ମୂଲ୍ୟ = (long)va_arg (args, unsigned LLONG);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_SIZE)
					ମୂଲ୍ୟ = va_arg (args, size_t);
#ifdef notyet
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_INTMAX)
					ମୂଲ୍ୟ = va_arg (args, uintmax_t);
#endif
				ଅନ୍ୟଥା
					ମୂଲ୍ୟ = (long)va_arg (args, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଯଦି (fmtint(buffer, &currlen, maxlen, ମୂଲ୍ୟ,
				    8, min, max, flags) == -1)
					ଯାଅ fail;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'u':
				flags |= DP_F_UNSIGNED;
				ଯଦି (cflags == DP_C_SHORT)
					ମୂଲ୍ୟ = va_arg (args, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_LONG)
					ମୂଲ୍ୟ = (long)va_arg (args, unsigned long ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_LLONG)
					ମୂଲ୍ୟ = (LLONG)va_arg (args, unsigned LLONG);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_SIZE)
					ମୂଲ୍ୟ = va_arg (args, size_t);
#ifdef notyet
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_INTMAX)
					ମୂଲ୍ୟ = va_arg (args, uintmax_t);
#endif
				ଅନ୍ୟଥା
					ମୂଲ୍ୟ = (long)va_arg (args, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଯଦି (fmtint(buffer, &currlen, maxlen, ମୂଲ୍ୟ,
				    10, min, max, flags) == -1)
					ଯାଅ fail;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'X':
				flags |= DP_F_UP;
			ସ୍ଥିତି 'x':
				flags |= DP_F_UNSIGNED;
				ଯଦି (cflags == DP_C_SHORT)
					ମୂଲ୍ୟ = va_arg (args, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_LONG)
					ମୂଲ୍ୟ = (long)va_arg (args, unsigned long ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_LLONG)
					ମୂଲ୍ୟ = (LLONG)va_arg (args, unsigned LLONG);
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_SIZE)
					ମୂଲ୍ୟ = va_arg (args, size_t);
#ifdef notyet
				ଅନ୍ୟଥା ଯଦି (cflags == DP_C_INTMAX)
					ମୂଲ୍ୟ = va_arg (args, uintmax_t);
#endif
				ଅନ୍ୟଥା
					ମୂଲ୍ୟ = (long)va_arg (args, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
				ଯଦି (fmtint(buffer, &currlen, maxlen, ମୂଲ୍ୟ,
				    16, min, max, flags) == -1)
					ଯାଅ fail;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'f':
				ଯଦି (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				ଅନ୍ୟଥା
					fvalue = va_arg (args, ଦ୍ୱିଗୁଣ);
				ଯଦି (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ଯାଅ fail;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'E':
				flags |= DP_F_UP;
			ସ୍ଥିତି 'e':
				ଯଦି (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				ଅନ୍ୟଥା
					fvalue = va_arg (args, ଦ୍ୱିଗୁଣ);
				ଯଦି (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ଯାଅ fail;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'G':
				flags |= DP_F_UP;
			ସ୍ଥିତି 'g':
				ଯଦି (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				ଅନ୍ୟଥା
					fvalue = va_arg (args, ଦ୍ୱିଗୁଣ);
				ଯଦି (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ଯାଅ fail;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, ପୂର୍ଣ୍ଣସଂଖ୍ୟା));
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 's':
				strvalue = va_arg (args, ଅକ୍ଷର *);
				ଯଦି (!strvalue) strvalue = "(NULL)";
				ଯଦି (max == -1) {
					max = strlen(strvalue);
				}
				ଯଦି (min > 0 && max >= 0 && min > max) max = min;
				ଯଦି (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					ଯାଅ fail;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି 'p':
				strvalue = va_arg (args, ଶୂନ୍ୟ *);
				ଯଦି (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					ଯାଅ fail;
				ଭାଙ୍ଗ;
#ଯଦି we_dont_want_this_in_openssh
			ସ୍ଥିତି 'n':
				ଯଦି (cflags == DP_C_SHORT) {
					short ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ଅଙ୍କ;
					ଅଙ୍କ = va_arg (args, short ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
					*ଅଙ୍କ = currlen;
				} ଅନ୍ୟଥା ଯଦି (cflags == DP_C_LONG) {
					long ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ଅଙ୍କ;
					ଅଙ୍କ = va_arg (args, long ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
					*ଅଙ୍କ = (long ପୂର୍ଣ୍ଣସଂଖ୍ୟା)currlen;
				} ଅନ୍ୟଥା ଯଦି (cflags == DP_C_LLONG) {
					LLONG *ଅଙ୍କ;
					ଅଙ୍କ = va_arg (args, LLONG *);
					*ଅଙ୍କ = (LLONG)currlen;
				} ଅନ୍ୟଥା ଯଦି (cflags == DP_C_SIZE) {
					ssize_t *ଅଙ୍କ;
					ଅଙ୍କ = va_arg (args, ssize_t *);
					*ଅଙ୍କ = (ssize_t)currlen;
				} ଅନ୍ୟଥା ଯଦି (cflags == DP_C_INTMAX) {
					intmax_t *ଅଙ୍କ;
					ଅଙ୍କ = va_arg (args, intmax_t *);
					*ଅଙ୍କ = (intmax_t)currlen;
				} ଅନ୍ୟଥା {
					ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ଅଙ୍କ;
					ଅଙ୍କ = va_arg (args, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *);
					*ଅଙ୍କ = currlen;
				}
				ଭାଙ୍ଗ;
#endif
			ସ୍ଥିତି '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				ଭାଙ୍ଗ;
			ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
				/* Unknown, skip */
				ଭାଙ୍ଗ;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି DP_S_DONE:
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			/* hmm? */
			ଭାଙ୍ଗ; /* some picky compilers need this */
		}
	}
	ଯଦି (maxlen != 0) {
		ଯଦି (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		ଅନ୍ୟଥା ଯଦି (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	ଫେରନ୍ତୁ currlen < INT_MAX ? (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)currlen : -1;
 fail:
	va_end(args);
	ଫେରନ୍ତୁ -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fmtstr(ଅକ୍ଷର *buffer, size_t *currlen, size_t maxlen,
    ଅକ୍ଷର *ମୂଲ୍ୟ, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags, ପୂର୍ଣ୍ଣସଂଖ୍ୟା min, ପୂର୍ଣ୍ଣସଂଖ୍ୟା max)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା padlen, strln;     /* amount to pad */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, ମୂଲ୍ୟ);
#endif
	ଯଦି (ମୂଲ୍ୟ == 0) {
		ମୂଲ୍ୟ = "<NULL>";
	}

	ପାଇଁ (strln = 0; strln < max && ମୂଲ୍ୟ[strln]; ++strln); /* strlen */
	padlen = min - strln;
	ଯଦି (padlen < 0)
		padlen = 0;
	ଯଦି (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	ଯେତେବେଳେ ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	ଯେତେବେଳେ (*ମୂଲ୍ୟ && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *ମୂଲ୍ୟ);
		ମୂଲ୍ୟ++;
		++cnt;
	}
	ଯେତେବେଳେ ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	ଫେରନ୍ତୁ 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fmtint(ଅକ୍ଷର *buffer, size_t *currlen, size_t maxlen,
    intmax_t ମୂଲ୍ୟ, ପୂର୍ଣ୍ଣସଂଖ୍ୟା base, ପୂର୍ଣ୍ଣସଂଖ୍ୟା min, ପୂର୍ଣ୍ଣସଂଖ୍ୟା max, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା signvalue = 0;
	unsigned LLONG uvalue;
	ଅକ୍ଷର convert[20];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା place = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା spadlen = 0; /* amount to space pad */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା zpadlen = 0; /* amount to zero pad */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା caps = 0;

	ଯଦି (max < 0)
		max = 0;

	uvalue = ମୂଲ୍ୟ;

	ଯଦି(!(flags & DP_F_UNSIGNED)) {
		ଯଦି( ମୂଲ୍ୟ < 0 ) {
			signvalue = '-';
			uvalue = -ମୂଲ୍ୟ;
		} ଅନ୍ୟଥା {
			ଯଦି (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			ଅନ୍ୟଥା ଯଦି (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	ଯଦି (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	କର {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} ଯେତେବେଳେ(uvalue && (place < 20));
	ଯଦି (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	ଯଦି (zpadlen < 0) zpadlen = 0;
	ଯଦି (spadlen < 0) spadlen = 0;
	ଯଦି (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	ଯଦି (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	ଯେତେବେଳେ (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	ଯଦି (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	ଯଦି (zpadlen > 0) {
		ଯେତେବେଳେ (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	ଯେତେବେଳେ (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	ଯେତେବେଳେ (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର LDOUBLE abs_val(LDOUBLE ମୂଲ୍ୟ)
{
	LDOUBLE result = ମୂଲ୍ୟ;

	ଯଦି (ମୂଲ୍ୟ < 0)
		result = -ମୂଲ୍ୟ;

	ଫେରନ୍ତୁ result;
}

ସ୍ଥିର LDOUBLE POW10(ପୂର୍ଣ୍ଣସଂଖ୍ୟା val)
{
	LDOUBLE result = 1;

	ଯେତେବେଳେ (val) {
		result *= 10;
		val--;
	}

	ଫେରନ୍ତୁ result;
}

ସ୍ଥିର LLONG ROUND(LDOUBLE ମୂଲ୍ୟ)
{
	LLONG intpart;

	intpart = (LLONG)ମୂଲ୍ୟ;
	ମୂଲ୍ୟ = ମୂଲ୍ୟ - intpart;
	ଯଦି (ମୂଲ୍ୟ >= 0.5) intpart++;

	ଫେରନ୍ତୁ intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
ସ୍ଥିର ଦ୍ୱିଗୁଣ my_modf(ଦ୍ୱିଗୁଣ x0, ଦ୍ୱିଗୁଣ *iptr)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	long l;
	ଦ୍ୱିଗୁଣ x = x0;
	ଦ୍ୱିଗୁଣ f = 1.0;

	ପାଇଁ (i=0;i<100;i++) {
		l = (long)x;
		ଯଦି (l <= (x+1) && l >= (x-1)) ଭାଙ୍ଗ;
		x *= 0.1;
		f *= 10.0;
	}

	ଯଦି (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି (i != 0) {
		ଦ୍ୱିଗୁଣ i2;
		ଦ୍ୱିଗୁଣ ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		ଫେରନ୍ତୁ ret;
	}

	(*iptr) = l;
	ଫେରନ୍ତୁ x - (*iptr);
}


ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fmtfp (ଅକ୍ଷର *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, ପୂର୍ଣ୍ଣସଂଖ୍ୟା min, ପୂର୍ଣ୍ଣସଂଖ୍ୟା max, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା signvalue = 0;
	ଦ୍ୱିଗୁଣ ufvalue;
	ଅକ୍ଷର iconvert[311];
	ଅକ୍ଷର fconvert[311];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା iplace = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fplace = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା padlen = 0; /* amount to pad */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା zpadlen = 0;
#ଯଦି 0
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା caps = 0;
#endif
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା idx;
	ଦ୍ୱିଗୁଣ intpart;
	ଦ୍ୱିଗୁଣ fracpart;
	ଦ୍ୱିଗୁଣ temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	ଯଦି (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	ଯଦି (fvalue < 0) {
		signvalue = '-';
	} ଅନ୍ୟଥା {
		ଯଦି (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} ଅନ୍ୟଥା {
			ଯଦି (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#ଯଦି 0
	ଯଦି (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#ଯଦି 0
	 ଯଦି (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	ଯଦି (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	ଯଦି (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	କର {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} ଯେତେବେଳେ (intpart && (iplace < 311));
	ଯଦି (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	ଯଦି (fracpart)
	{
		କର {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} ଯେତେବେଳେ(fracpart && (fplace < 311));
		ଯଦି (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	ଯଦି (zpadlen < 0) zpadlen = 0;
	ଯଦି (padlen < 0)
		padlen = 0;
	ଯଦି (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	ଯଦି ((flags & DP_F_ZERO) && (padlen > 0)) {
		ଯଦି (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		ଯେତେବେଳେ (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	ଯେତେବେଳେ (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	ଯଦି (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	ଯେତେବେଳେ (iplace > 0) {
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
	ଯଦି (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		ଯେତେବେଳେ (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		ଯେତେବେଳେ (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	ଯେତେବେଳେ (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	ଫେରନ୍ତୁ 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#ଯଦି !defined(HAVE_VSNPRINTF)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
vsnprintf (ଅକ୍ଷର *str, size_t ଗଣନା_2, ଅଚଳ ଅକ୍ଷର *fmt, va_list args)
{
	ଫେରନ୍ତୁ dopr(str, ଗଣନା_2, fmt, args);
}
#endif

#ଯଦି !defined(HAVE_SNPRINTF)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
snprintf(ଅକ୍ଷର *str, size_t ଗଣନା_2, SNPRINTF_CONST ଅକ୍ଷର *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, ଗଣନା_2, fmt, ap);
	va_end(ap);
	ଫେରନ୍ତୁ ret;
}
#endif
