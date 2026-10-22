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

#अन्तर्भाव "includes.h"

#जइ defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#जइ !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long द्विगुण
#अण्णहा
# define LDOUBLE द्विगुण
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#अण्णहा
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
#define DP_F_अङ्कः	(1 << 3)
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
	करेहि { \
		जइ (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			प्रत्यागम -1; \
		} \
		जइ (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} जाव (0)

स्थिर पूर्णाङ्क dopr(वर्ण *buffer, size_t maxlen, ध्रुव वर्ण *format,
    va_list args_in);
स्थिर पूर्णाङ्क fmtstr(वर्ण *buffer, size_t *currlen, size_t maxlen,
    वर्ण *मानम्, पूर्णाङ्क flags, पूर्णाङ्क min, पूर्णाङ्क max);
स्थिर पूर्णाङ्क fmtint(वर्ण *buffer, size_t *currlen, size_t maxlen,
    intmax_t मानम्, पूर्णाङ्क base, पूर्णाङ्क min, पूर्णाङ्क max, पूर्णाङ्क flags);
स्थिर पूर्णाङ्क fmtfp(वर्ण *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, पूर्णाङ्क min, पूर्णाङ्क max, पूर्णाङ्क flags);

स्थिर पूर्णाङ्क
dopr(वर्ण *buffer, size_t maxlen, ध्रुव वर्ण *format, va_list args_in)
{
	वर्ण ch;
	intmax_t मानम्;
	LDOUBLE fvalue;
	वर्ण *strvalue;
	पूर्णाङ्क min;
	पूर्णाङ्क max;
	पूर्णाङ्क state;
	पूर्णाङ्क flags;
	पूर्णाङ्क cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	जाव (state != DP_S_DONE) {
		जइ (ch == '\0')
			state = DP_S_DONE;

		विकल्प(state) {
		पक्ष DP_S_DEFAULT:
			जइ (ch == '%')
				state = DP_S_FLAGS;
			अण्णहा
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			भङ्ग;
		पक्ष DP_S_FLAGS:
			विकल्प (ch) {
			पक्ष '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				भङ्ग;
			पक्ष '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				भङ्ग;
			पक्ष ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				भङ्ग;
			पक्ष '#':
				flags |= DP_F_अङ्कः;
				ch = *format++;
				भङ्ग;
			पक्ष '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				भङ्ग;
			स्वभाव:
				state = DP_S_MIN;
				भङ्ग;
			}
			भङ्ग;
		पक्ष DP_S_MIN:
			जइ (isdigit((unsigned वर्ण)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} अण्णहा जइ (ch == '*') {
				min = va_arg (args, पूर्णाङ्क);
				ch = *format++;
				state = DP_S_DOT;
			} अण्णहा {
				state = DP_S_DOT;
			}
			भङ्ग;
		पक्ष DP_S_DOT:
			जइ (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} अण्णहा {
				state = DP_S_MOD;
			}
			भङ्ग;
		पक्ष DP_S_MAX:
			जइ (isdigit((unsigned वर्ण)ch)) {
				जइ (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} अण्णहा जइ (ch == '*') {
				max = va_arg (args, पूर्णाङ्क);
				ch = *format++;
				state = DP_S_MOD;
			} अण्णहा {
				state = DP_S_MOD;
			}
			भङ्ग;
		पक्ष DP_S_MOD:
			विकल्प (ch) {
			पक्ष 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				भङ्ग;
			पक्ष 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				भङ्ग;
			पक्ष 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				जइ (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				भङ्ग;
			पक्ष 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				भङ्ग;
			पक्ष 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				भङ्ग;
			स्वभाव:
				भङ्ग;
			}
			state = DP_S_CONV;
			भङ्ग;
		पक्ष DP_S_CONV:
			विकल्प (ch) {
			पक्ष 'd':
			पक्ष 'i':
				जइ (cflags == DP_C_SHORT)
					मानम् = va_arg (args, पूर्णाङ्क);
				अण्णहा जइ (cflags == DP_C_LONG)
					मानम् = va_arg (args, long पूर्णाङ्क);
				अण्णहा जइ (cflags == DP_C_LLONG)
					मानम् = va_arg (args, LLONG);
				अण्णहा जइ (cflags == DP_C_SIZE)
					मानम् = va_arg (args, ssize_t);
				अण्णहा जइ (cflags == DP_C_INTMAX)
					मानम् = va_arg (args, intmax_t);
				अण्णहा
					मानम् = va_arg (args, पूर्णाङ्क);
				जइ (fmtint(buffer, &currlen, maxlen,
				    मानम्, 10, min, max, flags) == -1)
					गच्छ fail;
				भङ्ग;
			पक्ष 'o':
				flags |= DP_F_UNSIGNED;
				जइ (cflags == DP_C_SHORT)
					मानम् = va_arg (args, unsigned पूर्णाङ्क);
				अण्णहा जइ (cflags == DP_C_LONG)
					मानम् = (long)va_arg (args, unsigned long पूर्णाङ्क);
				अण्णहा जइ (cflags == DP_C_LLONG)
					मानम् = (long)va_arg (args, unsigned LLONG);
				अण्णहा जइ (cflags == DP_C_SIZE)
					मानम् = va_arg (args, size_t);
#ifdef notyet
				अण्णहा जइ (cflags == DP_C_INTMAX)
					मानम् = va_arg (args, uintmax_t);
#endif
				अण्णहा
					मानम् = (long)va_arg (args, unsigned पूर्णाङ्क);
				जइ (fmtint(buffer, &currlen, maxlen, मानम्,
				    8, min, max, flags) == -1)
					गच्छ fail;
				भङ्ग;
			पक्ष 'u':
				flags |= DP_F_UNSIGNED;
				जइ (cflags == DP_C_SHORT)
					मानम् = va_arg (args, unsigned पूर्णाङ्क);
				अण्णहा जइ (cflags == DP_C_LONG)
					मानम् = (long)va_arg (args, unsigned long पूर्णाङ्क);
				अण्णहा जइ (cflags == DP_C_LLONG)
					मानम् = (LLONG)va_arg (args, unsigned LLONG);
				अण्णहा जइ (cflags == DP_C_SIZE)
					मानम् = va_arg (args, size_t);
#ifdef notyet
				अण्णहा जइ (cflags == DP_C_INTMAX)
					मानम् = va_arg (args, uintmax_t);
#endif
				अण्णहा
					मानम् = (long)va_arg (args, unsigned पूर्णाङ्क);
				जइ (fmtint(buffer, &currlen, maxlen, मानम्,
				    10, min, max, flags) == -1)
					गच्छ fail;
				भङ्ग;
			पक्ष 'X':
				flags |= DP_F_UP;
			पक्ष 'x':
				flags |= DP_F_UNSIGNED;
				जइ (cflags == DP_C_SHORT)
					मानम् = va_arg (args, unsigned पूर्णाङ्क);
				अण्णहा जइ (cflags == DP_C_LONG)
					मानम् = (long)va_arg (args, unsigned long पूर्णाङ्क);
				अण्णहा जइ (cflags == DP_C_LLONG)
					मानम् = (LLONG)va_arg (args, unsigned LLONG);
				अण्णहा जइ (cflags == DP_C_SIZE)
					मानम् = va_arg (args, size_t);
#ifdef notyet
				अण्णहा जइ (cflags == DP_C_INTMAX)
					मानम् = va_arg (args, uintmax_t);
#endif
				अण्णहा
					मानम् = (long)va_arg (args, unsigned पूर्णाङ्क);
				जइ (fmtint(buffer, &currlen, maxlen, मानम्,
				    16, min, max, flags) == -1)
					गच्छ fail;
				भङ्ग;
			पक्ष 'f':
				जइ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				अण्णहा
					fvalue = va_arg (args, द्विगुण);
				जइ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					गच्छ fail;
				भङ्ग;
			पक्ष 'E':
				flags |= DP_F_UP;
			पक्ष 'e':
				जइ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				अण्णहा
					fvalue = va_arg (args, द्विगुण);
				जइ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					गच्छ fail;
				भङ्ग;
			पक्ष 'G':
				flags |= DP_F_UP;
			पक्ष 'g':
				जइ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				अण्णहा
					fvalue = va_arg (args, द्विगुण);
				जइ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					गच्छ fail;
				भङ्ग;
			पक्ष 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, पूर्णाङ्क));
				भङ्ग;
			पक्ष 's':
				strvalue = va_arg (args, वर्ण *);
				जइ (!strvalue) strvalue = "(NULL)";
				जइ (max == -1) {
					max = strlen(strvalue);
				}
				जइ (min > 0 && max >= 0 && min > max) max = min;
				जइ (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					गच्छ fail;
				भङ्ग;
			पक्ष 'p':
				strvalue = va_arg (args, शून्य *);
				जइ (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					गच्छ fail;
				भङ्ग;
#जइ we_dont_want_this_in_openssh
			पक्ष 'n':
				जइ (cflags == DP_C_SHORT) {
					short पूर्णाङ्क *अङ्कः;
					अङ्कः = va_arg (args, short पूर्णाङ्क *);
					*अङ्कः = currlen;
				} अण्णहा जइ (cflags == DP_C_LONG) {
					long पूर्णाङ्क *अङ्कः;
					अङ्कः = va_arg (args, long पूर्णाङ्क *);
					*अङ्कः = (long पूर्णाङ्क)currlen;
				} अण्णहा जइ (cflags == DP_C_LLONG) {
					LLONG *अङ्कः;
					अङ्कः = va_arg (args, LLONG *);
					*अङ्कः = (LLONG)currlen;
				} अण्णहा जइ (cflags == DP_C_SIZE) {
					ssize_t *अङ्कः;
					अङ्कः = va_arg (args, ssize_t *);
					*अङ्कः = (ssize_t)currlen;
				} अण्णहा जइ (cflags == DP_C_INTMAX) {
					intmax_t *अङ्कः;
					अङ्कः = va_arg (args, intmax_t *);
					*अङ्कः = (intmax_t)currlen;
				} अण्णहा {
					पूर्णाङ्क *अङ्कः;
					अङ्कः = va_arg (args, पूर्णाङ्क *);
					*अङ्कः = currlen;
				}
				भङ्ग;
#endif
			पक्ष '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				भङ्ग;
			स्वभाव:
				/* Unknown, skip */
				भङ्ग;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			भङ्ग;
		पक्ष DP_S_DONE:
			भङ्ग;
		स्वभाव:
			/* hmm? */
			भङ्ग; /* some picky compilers need this */
		}
	}
	जइ (maxlen != 0) {
		जइ (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		अण्णहा जइ (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	प्रत्यागम currlen < INT_MAX ? (पूर्णाङ्क)currlen : -1;
 fail:
	va_end(args);
	प्रत्यागम -1;
}

स्थिर पूर्णाङ्क
fmtstr(वर्ण *buffer, size_t *currlen, size_t maxlen,
    वर्ण *मानम्, पूर्णाङ्क flags, पूर्णाङ्क min, पूर्णाङ्क max)
{
	पूर्णाङ्क padlen, strln;     /* amount to pad */
	पूर्णाङ्क cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, मानम्);
#endif
	जइ (मानम् == 0) {
		मानम् = "<NULL>";
	}

	प्रति (strln = 0; strln < max && मानम्[strln]; ++strln); /* strlen */
	padlen = min - strln;
	जइ (padlen < 0)
		padlen = 0;
	जइ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	जाव ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	जाव (*मानम् && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *मानम्);
		मानम्++;
		++cnt;
	}
	जाव ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	प्रत्यागम 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

स्थिर पूर्णाङ्क
fmtint(वर्ण *buffer, size_t *currlen, size_t maxlen,
    intmax_t मानम्, पूर्णाङ्क base, पूर्णाङ्क min, पूर्णाङ्क max, पूर्णाङ्क flags)
{
	पूर्णाङ्क signvalue = 0;
	unsigned LLONG uvalue;
	वर्ण convert[20];
	पूर्णाङ्क place = 0;
	पूर्णाङ्क spadlen = 0; /* amount to space pad */
	पूर्णाङ्क zpadlen = 0; /* amount to zero pad */
	पूर्णाङ्क caps = 0;

	जइ (max < 0)
		max = 0;

	uvalue = मानम्;

	जइ(!(flags & DP_F_UNSIGNED)) {
		जइ( मानम् < 0 ) {
			signvalue = '-';
			uvalue = -मानम्;
		} अण्णहा {
			जइ (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			अण्णहा जइ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	जइ (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	करेहि {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} जाव(uvalue && (place < 20));
	जइ (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	जइ (zpadlen < 0) zpadlen = 0;
	जइ (spadlen < 0) spadlen = 0;
	जइ (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	जइ (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	जाव (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	जइ (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	जइ (zpadlen > 0) {
		जाव (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	जाव (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	जाव (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	प्रत्यागम 0;
}

स्थिर LDOUBLE abs_val(LDOUBLE मानम्)
{
	LDOUBLE result = मानम्;

	जइ (मानम् < 0)
		result = -मानम्;

	प्रत्यागम result;
}

स्थिर LDOUBLE POW10(पूर्णाङ्क val)
{
	LDOUBLE result = 1;

	जाव (val) {
		result *= 10;
		val--;
	}

	प्रत्यागम result;
}

स्थिर LLONG ROUND(LDOUBLE मानम्)
{
	LLONG intpart;

	intpart = (LLONG)मानम्;
	मानम् = मानम् - intpart;
	जइ (मानम् >= 0.5) intpart++;

	प्रत्यागम intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
स्थिर द्विगुण my_modf(द्विगुण x0, द्विगुण *iptr)
{
	पूर्णाङ्क i;
	long l;
	द्विगुण x = x0;
	द्विगुण f = 1.0;

	प्रति (i=0;i<100;i++) {
		l = (long)x;
		जइ (l <= (x+1) && l >= (x-1)) भङ्ग;
		x *= 0.1;
		f *= 10.0;
	}

	जइ (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		प्रत्यागम 0;
	}

	जइ (i != 0) {
		द्विगुण i2;
		द्विगुण ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		प्रत्यागम ret;
	}

	(*iptr) = l;
	प्रत्यागम x - (*iptr);
}


स्थिर पूर्णाङ्क
fmtfp (वर्ण *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, पूर्णाङ्क min, पूर्णाङ्क max, पूर्णाङ्क flags)
{
	पूर्णाङ्क signvalue = 0;
	द्विगुण ufvalue;
	वर्ण iconvert[311];
	वर्ण fconvert[311];
	पूर्णाङ्क iplace = 0;
	पूर्णाङ्क fplace = 0;
	पूर्णाङ्क padlen = 0; /* amount to pad */
	पूर्णाङ्क zpadlen = 0;
#जइ 0
	पूर्णाङ्क caps = 0;
#endif
	पूर्णाङ्क idx;
	द्विगुण intpart;
	द्विगुण fracpart;
	द्विगुण temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	जइ (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	जइ (fvalue < 0) {
		signvalue = '-';
	} अण्णहा {
		जइ (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} अण्णहा {
			जइ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#जइ 0
	जइ (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#जइ 0
	 जइ (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	जइ (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	जइ (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	करेहि {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (पूर्णाङ्क) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} जाव (intpart && (iplace < 311));
	जइ (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	जइ (fracpart)
	{
		करेहि {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (पूर्णाङ्क) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} जाव(fracpart && (fplace < 311));
		जइ (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	जइ (zpadlen < 0) zpadlen = 0;
	जइ (padlen < 0)
		padlen = 0;
	जइ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	जइ ((flags & DP_F_ZERO) && (padlen > 0)) {
		जइ (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		जाव (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	जाव (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	जइ (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	जाव (iplace > 0) {
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
	जइ (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		जाव (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		जाव (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	जाव (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	प्रत्यागम 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#जइ !defined(HAVE_VSNPRINTF)
पूर्णाङ्क
vsnprintf (वर्ण *str, size_t गणनम्, ध्रुव वर्ण *fmt, va_list args)
{
	प्रत्यागम dopr(str, गणनम्, fmt, args);
}
#endif

#जइ !defined(HAVE_SNPRINTF)
पूर्णाङ्क
snprintf(वर्ण *str, size_t गणनम्, SNPRINTF_CONST वर्ण *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, गणनम्, fmt, ap);
	va_end(ap);
	प्रत्यागम ret;
}
#endif
