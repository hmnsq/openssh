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

#यदि defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#यदि !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE दीर्घ द्विगुण
#अन्यथा
# define LDOUBLE द्विगुण
#endif

#ifdef HAVE_LONG_LONG
# define LLONG दीर्घ दीर्घ
#अन्यथा
# define LLONG दीर्घ
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
#define DP_F_अङ्क	(1 << 3)
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
	गर { \
		यदि (pos + 1 >= पूर्णांक_उच्च) { \
			त्रुटि_सं = दुस्फल; \
			फर्काऊ -1; \
		} \
		यदि (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} जबसम्म (0)

स्थिर पूर्णाङ्क dopr(वर्ण *buffer, माप_प्रकार maxlen, अचर वर्ण *format,
    बहु_सूची args_in);
स्थिर पूर्णाङ्क fmtstr(वर्ण *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    वर्ण *मान, पूर्णाङ्क flags, पूर्णाङ्क min, पूर्णाङ्क max);
स्थिर पूर्णाङ्क fmtint(वर्ण *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    intmax_t मान, पूर्णाङ्क base, पूर्णाङ्क min, पूर्णाङ्क max, पूर्णाङ्क flags);
स्थिर पूर्णाङ्क fmtfp(वर्ण *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    LDOUBLE fvalue, पूर्णाङ्क min, पूर्णाङ्क max, पूर्णाङ्क flags);

स्थिर पूर्णाङ्क
dopr(वर्ण *buffer, माप_प्रकार maxlen, अचर वर्ण *format, बहु_सूची args_in)
{
	वर्ण ch;
	intmax_t मान;
	LDOUBLE fvalue;
	वर्ण *strvalue;
	पूर्णाङ्क min;
	पूर्णाङ्क max;
	पूर्णाङ्क state;
	पूर्णाङ्क flags;
	पूर्णाङ्क cflags;
	माप_प्रकार currlen;
	बहु_सूची args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	जबसम्म (state != DP_S_DONE) {
		यदि (ch == '\0')
			state = DP_S_DONE;

		विकल्प(state) {
		पक्ष DP_S_DEFAULT:
			यदि (ch == '%')
				state = DP_S_FLAGS;
			अन्यथा
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			रोक;
		पक्ष DP_S_FLAGS:
			विकल्प (ch) {
			पक्ष '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				रोक;
			पक्ष '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				रोक;
			पक्ष ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				रोक;
			पक्ष '#':
				flags |= DP_F_अङ्क;
				ch = *format++;
				रोक;
			पक्ष '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				रोक;
			स्वभाव:
				state = DP_S_MIN;
				रोक;
			}
			रोक;
		पक्ष DP_S_MIN:
			यदि (है_अंक((अचिन्हित वर्ण)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} अन्यथा यदि (ch == '*') {
				min = बहु_तर्क (args, पूर्णाङ्क);
				ch = *format++;
				state = DP_S_DOT;
			} अन्यथा {
				state = DP_S_DOT;
			}
			रोक;
		पक्ष DP_S_DOT:
			यदि (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} अन्यथा {
				state = DP_S_MOD;
			}
			रोक;
		पक्ष DP_S_MAX:
			यदि (है_अंक((अचिन्हित वर्ण)ch)) {
				यदि (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} अन्यथा यदि (ch == '*') {
				max = बहु_तर्क (args, पूर्णाङ्क);
				ch = *format++;
				state = DP_S_MOD;
			} अन्यथा {
				state = DP_S_MOD;
			}
			रोक;
		पक्ष DP_S_MOD:
			विकल्प (ch) {
			पक्ष 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				रोक;
			पक्ष 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				रोक;
			पक्ष 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				यदि (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				रोक;
			पक्ष 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				रोक;
			पक्ष 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				रोक;
			स्वभाव:
				रोक;
			}
			state = DP_S_CONV;
			रोक;
		पक्ष DP_S_CONV:
			विकल्प (ch) {
			पक्ष 'd':
			पक्ष 'i':
				यदि (cflags == DP_C_SHORT)
					मान = बहु_तर्क (args, पूर्णाङ्क);
				अन्यथा यदि (cflags == DP_C_LONG)
					मान = बहु_तर्क (args, दीर्घ पूर्णाङ्क);
				अन्यथा यदि (cflags == DP_C_LLONG)
					मान = बहु_तर्क (args, LLONG);
				अन्यथा यदि (cflags == DP_C_SIZE)
					मान = बहु_तर्क (args, ssize_t);
				अन्यथा यदि (cflags == DP_C_INTMAX)
					मान = बहु_तर्क (args, intmax_t);
				अन्यथा
					मान = बहु_तर्क (args, पूर्णाङ्क);
				यदि (fmtint(buffer, &currlen, maxlen,
				    मान, 10, min, max, flags) == -1)
					गच्छ fail;
				रोक;
			पक्ष 'o':
				flags |= DP_F_UNSIGNED;
				यदि (cflags == DP_C_SHORT)
					मान = बहु_तर्क (args, अचिन्हित पूर्णाङ्क);
				अन्यथा यदि (cflags == DP_C_LONG)
					मान = (दीर्घ)बहु_तर्क (args, अचिन्हित दीर्घ पूर्णाङ्क);
				अन्यथा यदि (cflags == DP_C_LLONG)
					मान = (दीर्घ)बहु_तर्क (args, अचिन्हित LLONG);
				अन्यथा यदि (cflags == DP_C_SIZE)
					मान = बहु_तर्क (args, माप_प्रकार);
#ifdef notyet
				अन्यथा यदि (cflags == DP_C_INTMAX)
					मान = बहु_तर्क (args, uintmax_t);
#endif
				अन्यथा
					मान = (दीर्घ)बहु_तर्क (args, अचिन्हित पूर्णाङ्क);
				यदि (fmtint(buffer, &currlen, maxlen, मान,
				    8, min, max, flags) == -1)
					गच्छ fail;
				रोक;
			पक्ष 'u':
				flags |= DP_F_UNSIGNED;
				यदि (cflags == DP_C_SHORT)
					मान = बहु_तर्क (args, अचिन्हित पूर्णाङ्क);
				अन्यथा यदि (cflags == DP_C_LONG)
					मान = (दीर्घ)बहु_तर्क (args, अचिन्हित दीर्घ पूर्णाङ्क);
				अन्यथा यदि (cflags == DP_C_LLONG)
					मान = (LLONG)बहु_तर्क (args, अचिन्हित LLONG);
				अन्यथा यदि (cflags == DP_C_SIZE)
					मान = बहु_तर्क (args, माप_प्रकार);
#ifdef notyet
				अन्यथा यदि (cflags == DP_C_INTMAX)
					मान = बहु_तर्क (args, uintmax_t);
#endif
				अन्यथा
					मान = (दीर्घ)बहु_तर्क (args, अचिन्हित पूर्णाङ्क);
				यदि (fmtint(buffer, &currlen, maxlen, मान,
				    10, min, max, flags) == -1)
					गच्छ fail;
				रोक;
			पक्ष 'X':
				flags |= DP_F_UP;
			पक्ष 'x':
				flags |= DP_F_UNSIGNED;
				यदि (cflags == DP_C_SHORT)
					मान = बहु_तर्क (args, अचिन्हित पूर्णाङ्क);
				अन्यथा यदि (cflags == DP_C_LONG)
					मान = (दीर्घ)बहु_तर्क (args, अचिन्हित दीर्घ पूर्णाङ्क);
				अन्यथा यदि (cflags == DP_C_LLONG)
					मान = (LLONG)बहु_तर्क (args, अचिन्हित LLONG);
				अन्यथा यदि (cflags == DP_C_SIZE)
					मान = बहु_तर्क (args, माप_प्रकार);
#ifdef notyet
				अन्यथा यदि (cflags == DP_C_INTMAX)
					मान = बहु_तर्क (args, uintmax_t);
#endif
				अन्यथा
					मान = (दीर्घ)बहु_तर्क (args, अचिन्हित पूर्णाङ्क);
				यदि (fmtint(buffer, &currlen, maxlen, मान,
				    16, min, max, flags) == -1)
					गच्छ fail;
				रोक;
			पक्ष 'f':
				यदि (cflags == DP_C_LDOUBLE)
					fvalue = बहु_तर्क (args, LDOUBLE);
				अन्यथा
					fvalue = बहु_तर्क (args, द्विगुण);
				यदि (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					गच्छ fail;
				रोक;
			पक्ष 'E':
				flags |= DP_F_UP;
			पक्ष 'e':
				यदि (cflags == DP_C_LDOUBLE)
					fvalue = बहु_तर्क (args, LDOUBLE);
				अन्यथा
					fvalue = बहु_तर्क (args, द्विगुण);
				यदि (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					गच्छ fail;
				रोक;
			पक्ष 'G':
				flags |= DP_F_UP;
			पक्ष 'g':
				यदि (cflags == DP_C_LDOUBLE)
					fvalue = बहु_तर्क (args, LDOUBLE);
				अन्यथा
					fvalue = बहु_तर्क (args, द्विगुण);
				यदि (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					गच्छ fail;
				रोक;
			पक्ष 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    बहु_तर्क (args, पूर्णाङ्क));
				रोक;
			पक्ष 's':
				strvalue = बहु_तर्क (args, वर्ण *);
				यदि (!strvalue) strvalue = "(NULL)";
				यदि (max == -1) {
					max = म_माप(strvalue);
				}
				यदि (min > 0 && max >= 0 && min > max) max = min;
				यदि (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					गच्छ fail;
				रोक;
			पक्ष 'p':
				strvalue = बहु_तर्क (args, शून्य *);
				यदि (fmtint(buffer, &currlen, maxlen,
				    (दीर्घ) strvalue, 16, min, max, flags) == -1)
					गच्छ fail;
				रोक;
#यदि we_dont_want_this_in_openssh
			पक्ष 'n':
				यदि (cflags == DP_C_SHORT) {
					लघु पूर्णाङ्क *अङ्क;
					अङ्क = बहु_तर्क (args, लघु पूर्णाङ्क *);
					*अङ्क = currlen;
				} अन्यथा यदि (cflags == DP_C_LONG) {
					दीर्घ पूर्णाङ्क *अङ्क;
					अङ्क = बहु_तर्क (args, दीर्घ पूर्णाङ्क *);
					*अङ्क = (दीर्घ पूर्णाङ्क)currlen;
				} अन्यथा यदि (cflags == DP_C_LLONG) {
					LLONG *अङ्क;
					अङ्क = बहु_तर्क (args, LLONG *);
					*अङ्क = (LLONG)currlen;
				} अन्यथा यदि (cflags == DP_C_SIZE) {
					ssize_t *अङ्क;
					अङ्क = बहु_तर्क (args, ssize_t *);
					*अङ्क = (ssize_t)currlen;
				} अन्यथा यदि (cflags == DP_C_INTMAX) {
					intmax_t *अङ्क;
					अङ्क = बहु_तर्क (args, intmax_t *);
					*अङ्क = (intmax_t)currlen;
				} अन्यथा {
					पूर्णाङ्क *अङ्क;
					अङ्क = बहु_तर्क (args, पूर्णाङ्क *);
					*अङ्क = currlen;
				}
				रोक;
#endif
			पक्ष '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				रोक;
			स्वभाव:
				/* Unknown, skip */
				रोक;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			रोक;
		पक्ष DP_S_DONE:
			रोक;
		स्वभाव:
			/* hmm? */
			रोक; /* some picky compilers need this */
		}
	}
	यदि (maxlen != 0) {
		यदि (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		अन्यथा यदि (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	बहु_पूर्ण(args);
	फर्काऊ currlen < पूर्णांक_उच्च ? (पूर्णाङ्क)currlen : -1;
 fail:
	बहु_पूर्ण(args);
	फर्काऊ -1;
}

स्थिर पूर्णाङ्क
fmtstr(वर्ण *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    वर्ण *मान, पूर्णाङ्क flags, पूर्णाङ्क min, पूर्णाङ्क max)
{
	पूर्णाङ्क padlen, strln;     /* amount to pad */
	पूर्णाङ्क cnt = 0;

#ifdef DEBUG_SNPRINTF
	म_लिखो("fmtstr min=%d max=%d s=[%s]\n", min, max, मान);
#endif
	यदि (मान == 0) {
		मान = "<NULL>";
	}

	लागि (strln = 0; strln < max && मान[strln]; ++strln); /* strlen */
	padlen = min - strln;
	यदि (padlen < 0)
		padlen = 0;
	यदि (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	जबसम्म ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	जबसम्म (*मान && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *मान);
		मान++;
		++cnt;
	}
	जबसम्म ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	फर्काऊ 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

स्थिर पूर्णाङ्क
fmtint(वर्ण *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    intmax_t मान, पूर्णाङ्क base, पूर्णाङ्क min, पूर्णाङ्क max, पूर्णाङ्क flags)
{
	पूर्णाङ्क signvalue = 0;
	अचिन्हित LLONG uvalue;
	वर्ण convert[20];
	पूर्णाङ्क place = 0;
	पूर्णाङ्क spadlen = 0; /* amount to space pad */
	पूर्णाङ्क zpadlen = 0; /* amount to zero pad */
	पूर्णाङ्क caps = 0;

	यदि (max < 0)
		max = 0;

	uvalue = मान;

	यदि(!(flags & DP_F_UNSIGNED)) {
		यदि( मान < 0 ) {
			signvalue = '-';
			uvalue = -मान;
		} अन्यथा {
			यदि (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			अन्यथा यदि (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	यदि (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	गर {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (अचिन्हित)base  ];
		uvalue = (uvalue / (अचिन्हित)base );
	} जबसम्म(uvalue && (place < 20));
	यदि (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	यदि (zpadlen < 0) zpadlen = 0;
	यदि (spadlen < 0) spadlen = 0;
	यदि (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	यदि (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	म_लिखो("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	जबसम्म (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	यदि (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	यदि (zpadlen > 0) {
		जबसम्म (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	जबसम्म (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	जबसम्म (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	फर्काऊ 0;
}

स्थिर LDOUBLE abs_val(LDOUBLE मान)
{
	LDOUBLE result = मान;

	यदि (मान < 0)
		result = -मान;

	फर्काऊ result;
}

स्थिर LDOUBLE POW10(पूर्णाङ्क val)
{
	LDOUBLE result = 1;

	जबसम्म (val) {
		result *= 10;
		val--;
	}

	फर्काऊ result;
}

स्थिर LLONG ROUND(LDOUBLE मान)
{
	LLONG intpart;

	intpart = (LLONG)मान;
	मान = मान - intpart;
	यदि (मान >= 0.5) intpart++;

	फर्काऊ intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
स्थिर द्विगुण my_modf(द्विगुण x0, द्विगुण *iptr)
{
	पूर्णाङ्क i;
	दीर्घ l;
	द्विगुण x = x0;
	द्विगुण f = 1.0;

	लागि (i=0;i<100;i++) {
		l = (दीर्घ)x;
		यदि (l <= (x+1) && l >= (x-1)) रोक;
		x *= 0.1;
		f *= 10.0;
	}

	यदि (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		फर्काऊ 0;
	}

	यदि (i != 0) {
		द्विगुण i2;
		द्विगुण ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		फर्काऊ ret;
	}

	(*iptr) = l;
	फर्काऊ x - (*iptr);
}


स्थिर पूर्णाङ्क
fmtfp (वर्ण *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
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
#यदि 0
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
	यदि (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	यदि (fvalue < 0) {
		signvalue = '-';
	} अन्यथा {
		यदि (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} अन्यथा {
			यदि (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#यदि 0
	यदि (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#यदि 0
	 यदि (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	यदि (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	यदि (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	गर {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (पूर्णाङ्क) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} जबसम्म (intpart && (iplace < 311));
	यदि (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	यदि (fracpart)
	{
		गर {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (पूर्णाङ्क) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} जबसम्म(fracpart && (fplace < 311));
		यदि (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	यदि (zpadlen < 0) zpadlen = 0;
	यदि (padlen < 0)
		padlen = 0;
	यदि (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	यदि ((flags & DP_F_ZERO) && (padlen > 0)) {
		यदि (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		जबसम्म (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	जबसम्म (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	यदि (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	जबसम्म (iplace > 0) {
		--iplace;
		DOPR_OUTCH(buffer, *currlen, maxlen, iconvert[iplace]);
	}

#ifdef DEBUG_SNPRINTF
	म_लिखो("fmtfp: fplace=%d zpadlen=%d\n", fplace, zpadlen);
#endif

	/*
	 * Decimal point.  This should probably use locale to find the correct
	 * char to print out.
	 */
	यदि (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		जबसम्म (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		जबसम्म (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	जबसम्म (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	फर्काऊ 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#यदि !defined(HAVE_VSNPRINTF)
पूर्णाङ्क
vsnprintf (वर्ण *str, माप_प्रकार गन्ती, अचर वर्ण *fmt, बहु_सूची args)
{
	फर्काऊ dopr(str, गन्ती, fmt, args);
}
#endif

#यदि !defined(HAVE_SNPRINTF)
पूर्णाङ्क
snprintf(वर्ण *str, माप_प्रकार गन्ती, SNPRINTF_CONST वर्ण *fmt, ...)
{
	माप_प्रकार ret;
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	ret = vsnprintf(str, गन्ती, fmt, ap);
	बहु_पूर्ण(ap);
	फर्काऊ ret;
}
#endif
