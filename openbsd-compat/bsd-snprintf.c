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

#जर defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#जर !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

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
#define DP_F_अंक	(1 << 3)
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
	करा { \
		जर (pos + 1 >= पूर्णांक_उच्च) { \
			त्रुटि_सं = दुस्फल; \
			परत -1; \
		} \
		जर (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} पर्यंत (0)

स्थिर पूर्णांक dopr(अक्षर *buffer, माप_प्रकार maxlen, स्थिरांक अक्षर *format,
    बहु_सूची args_in);
स्थिर पूर्णांक fmtstr(अक्षर *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    अक्षर *मूल्य, पूर्णांक flags, पूर्णांक min, पूर्णांक max);
स्थिर पूर्णांक fmtint(अक्षर *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    intmax_t मूल्य, पूर्णांक base, पूर्णांक min, पूर्णांक max, पूर्णांक flags);
स्थिर पूर्णांक fmtfp(अक्षर *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    LDOUBLE fvalue, पूर्णांक min, पूर्णांक max, पूर्णांक flags);

स्थिर पूर्णांक
dopr(अक्षर *buffer, माप_प्रकार maxlen, स्थिरांक अक्षर *format, बहु_सूची args_in)
{
	अक्षर ch;
	intmax_t मूल्य;
	LDOUBLE fvalue;
	अक्षर *strvalue;
	पूर्णांक min;
	पूर्णांक max;
	पूर्णांक state;
	पूर्णांक flags;
	पूर्णांक cflags;
	माप_प्रकार currlen;
	बहु_सूची args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	पर्यंत (state != DP_S_DONE) {
		जर (ch == '\0')
			state = DP_S_DONE;

		निवड(state) {
		स्थिती DP_S_DEFAULT:
			जर (ch == '%')
				state = DP_S_FLAGS;
			अन्यथा
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			थांबा;
		स्थिती DP_S_FLAGS:
			निवड (ch) {
			स्थिती '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				थांबा;
			स्थिती '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				थांबा;
			स्थिती ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				थांबा;
			स्थिती '#':
				flags |= DP_F_अंक;
				ch = *format++;
				थांबा;
			स्थिती '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				थांबा;
			पूर्वनिर्धारित:
				state = DP_S_MIN;
				थांबा;
			}
			थांबा;
		स्थिती DP_S_MIN:
			जर (है_अंक((अचिन्हित अक्षर)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} अन्यथा जर (ch == '*') {
				min = बहु_तर्क (args, पूर्णांक);
				ch = *format++;
				state = DP_S_DOT;
			} अन्यथा {
				state = DP_S_DOT;
			}
			थांबा;
		स्थिती DP_S_DOT:
			जर (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} अन्यथा {
				state = DP_S_MOD;
			}
			थांबा;
		स्थिती DP_S_MAX:
			जर (है_अंक((अचिन्हित अक्षर)ch)) {
				जर (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} अन्यथा जर (ch == '*') {
				max = बहु_तर्क (args, पूर्णांक);
				ch = *format++;
				state = DP_S_MOD;
			} अन्यथा {
				state = DP_S_MOD;
			}
			थांबा;
		स्थिती DP_S_MOD:
			निवड (ch) {
			स्थिती 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				थांबा;
			स्थिती 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				थांबा;
			स्थिती 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				जर (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				थांबा;
			स्थिती 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				थांबा;
			स्थिती 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				थांबा;
			पूर्वनिर्धारित:
				थांबा;
			}
			state = DP_S_CONV;
			थांबा;
		स्थिती DP_S_CONV:
			निवड (ch) {
			स्थिती 'd':
			स्थिती 'i':
				जर (cflags == DP_C_SHORT)
					मूल्य = बहु_तर्क (args, पूर्णांक);
				अन्यथा जर (cflags == DP_C_LONG)
					मूल्य = बहु_तर्क (args, दीर्घ पूर्णांक);
				अन्यथा जर (cflags == DP_C_LLONG)
					मूल्य = बहु_तर्क (args, LLONG);
				अन्यथा जर (cflags == DP_C_SIZE)
					मूल्य = बहु_तर्क (args, ssize_t);
				अन्यथा जर (cflags == DP_C_INTMAX)
					मूल्य = बहु_तर्क (args, intmax_t);
				अन्यथा
					मूल्य = बहु_तर्क (args, पूर्णांक);
				जर (fmtint(buffer, &currlen, maxlen,
				    मूल्य, 10, min, max, flags) == -1)
					जा fail;
				थांबा;
			स्थिती 'o':
				flags |= DP_F_UNSIGNED;
				जर (cflags == DP_C_SHORT)
					मूल्य = बहु_तर्क (args, अचिन्हित पूर्णांक);
				अन्यथा जर (cflags == DP_C_LONG)
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित दीर्घ पूर्णांक);
				अन्यथा जर (cflags == DP_C_LLONG)
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित LLONG);
				अन्यथा जर (cflags == DP_C_SIZE)
					मूल्य = बहु_तर्क (args, माप_प्रकार);
#ifdef notyet
				अन्यथा जर (cflags == DP_C_INTMAX)
					मूल्य = बहु_तर्क (args, uintmax_t);
#endif
				अन्यथा
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित पूर्णांक);
				जर (fmtint(buffer, &currlen, maxlen, मूल्य,
				    8, min, max, flags) == -1)
					जा fail;
				थांबा;
			स्थिती 'u':
				flags |= DP_F_UNSIGNED;
				जर (cflags == DP_C_SHORT)
					मूल्य = बहु_तर्क (args, अचिन्हित पूर्णांक);
				अन्यथा जर (cflags == DP_C_LONG)
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित दीर्घ पूर्णांक);
				अन्यथा जर (cflags == DP_C_LLONG)
					मूल्य = (LLONG)बहु_तर्क (args, अचिन्हित LLONG);
				अन्यथा जर (cflags == DP_C_SIZE)
					मूल्य = बहु_तर्क (args, माप_प्रकार);
#ifdef notyet
				अन्यथा जर (cflags == DP_C_INTMAX)
					मूल्य = बहु_तर्क (args, uintmax_t);
#endif
				अन्यथा
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित पूर्णांक);
				जर (fmtint(buffer, &currlen, maxlen, मूल्य,
				    10, min, max, flags) == -1)
					जा fail;
				थांबा;
			स्थिती 'X':
				flags |= DP_F_UP;
			स्थिती 'x':
				flags |= DP_F_UNSIGNED;
				जर (cflags == DP_C_SHORT)
					मूल्य = बहु_तर्क (args, अचिन्हित पूर्णांक);
				अन्यथा जर (cflags == DP_C_LONG)
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित दीर्घ पूर्णांक);
				अन्यथा जर (cflags == DP_C_LLONG)
					मूल्य = (LLONG)बहु_तर्क (args, अचिन्हित LLONG);
				अन्यथा जर (cflags == DP_C_SIZE)
					मूल्य = बहु_तर्क (args, माप_प्रकार);
#ifdef notyet
				अन्यथा जर (cflags == DP_C_INTMAX)
					मूल्य = बहु_तर्क (args, uintmax_t);
#endif
				अन्यथा
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित पूर्णांक);
				जर (fmtint(buffer, &currlen, maxlen, मूल्य,
				    16, min, max, flags) == -1)
					जा fail;
				थांबा;
			स्थिती 'f':
				जर (cflags == DP_C_LDOUBLE)
					fvalue = बहु_तर्क (args, LDOUBLE);
				अन्यथा
					fvalue = बहु_तर्क (args, द्विगुण);
				जर (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					जा fail;
				थांबा;
			स्थिती 'E':
				flags |= DP_F_UP;
			स्थिती 'e':
				जर (cflags == DP_C_LDOUBLE)
					fvalue = बहु_तर्क (args, LDOUBLE);
				अन्यथा
					fvalue = बहु_तर्क (args, द्विगुण);
				जर (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					जा fail;
				थांबा;
			स्थिती 'G':
				flags |= DP_F_UP;
			स्थिती 'g':
				जर (cflags == DP_C_LDOUBLE)
					fvalue = बहु_तर्क (args, LDOUBLE);
				अन्यथा
					fvalue = बहु_तर्क (args, द्विगुण);
				जर (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					जा fail;
				थांबा;
			स्थिती 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    बहु_तर्क (args, पूर्णांक));
				थांबा;
			स्थिती 's':
				strvalue = बहु_तर्क (args, अक्षर *);
				जर (!strvalue) strvalue = "(NULL)";
				जर (max == -1) {
					max = म_माप(strvalue);
				}
				जर (min > 0 && max >= 0 && min > max) max = min;
				जर (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					जा fail;
				थांबा;
			स्थिती 'p':
				strvalue = बहु_तर्क (args, शून्य *);
				जर (fmtint(buffer, &currlen, maxlen,
				    (दीर्घ) strvalue, 16, min, max, flags) == -1)
					जा fail;
				थांबा;
#जर we_dont_want_this_in_openssh
			स्थिती 'n':
				जर (cflags == DP_C_SHORT) {
					लघु पूर्णांक *अंक;
					अंक = बहु_तर्क (args, लघु पूर्णांक *);
					*अंक = currlen;
				} अन्यथा जर (cflags == DP_C_LONG) {
					दीर्घ पूर्णांक *अंक;
					अंक = बहु_तर्क (args, दीर्घ पूर्णांक *);
					*अंक = (दीर्घ पूर्णांक)currlen;
				} अन्यथा जर (cflags == DP_C_LLONG) {
					LLONG *अंक;
					अंक = बहु_तर्क (args, LLONG *);
					*अंक = (LLONG)currlen;
				} अन्यथा जर (cflags == DP_C_SIZE) {
					ssize_t *अंक;
					अंक = बहु_तर्क (args, ssize_t *);
					*अंक = (ssize_t)currlen;
				} अन्यथा जर (cflags == DP_C_INTMAX) {
					intmax_t *अंक;
					अंक = बहु_तर्क (args, intmax_t *);
					*अंक = (intmax_t)currlen;
				} अन्यथा {
					पूर्णांक *अंक;
					अंक = बहु_तर्क (args, पूर्णांक *);
					*अंक = currlen;
				}
				थांबा;
#endif
			स्थिती '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				थांबा;
			पूर्वनिर्धारित:
				/* Unknown, skip */
				थांबा;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			थांबा;
		स्थिती DP_S_DONE:
			थांबा;
		पूर्वनिर्धारित:
			/* hmm? */
			थांबा; /* some picky compilers need this */
		}
	}
	जर (maxlen != 0) {
		जर (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		अन्यथा जर (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	बहु_पूर्ण(args);
	परत currlen < पूर्णांक_उच्च ? (पूर्णांक)currlen : -1;
 fail:
	बहु_पूर्ण(args);
	परत -1;
}

स्थिर पूर्णांक
fmtstr(अक्षर *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    अक्षर *मूल्य, पूर्णांक flags, पूर्णांक min, पूर्णांक max)
{
	पूर्णांक padlen, strln;     /* amount to pad */
	पूर्णांक cnt = 0;

#ifdef DEBUG_SNPRINTF
	म_लिखो("fmtstr min=%d max=%d s=[%s]\n", min, max, मूल्य);
#endif
	जर (मूल्य == 0) {
		मूल्य = "<NULL>";
	}

	साठी (strln = 0; strln < max && मूल्य[strln]; ++strln); /* strlen */
	padlen = min - strln;
	जर (padlen < 0)
		padlen = 0;
	जर (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	पर्यंत ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	पर्यंत (*मूल्य && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *मूल्य);
		मूल्य++;
		++cnt;
	}
	पर्यंत ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	परत 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

स्थिर पूर्णांक
fmtint(अक्षर *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    intmax_t मूल्य, पूर्णांक base, पूर्णांक min, पूर्णांक max, पूर्णांक flags)
{
	पूर्णांक signvalue = 0;
	अचिन्हित LLONG uvalue;
	अक्षर convert[20];
	पूर्णांक place = 0;
	पूर्णांक spadlen = 0; /* amount to space pad */
	पूर्णांक zpadlen = 0; /* amount to zero pad */
	पूर्णांक caps = 0;

	जर (max < 0)
		max = 0;

	uvalue = मूल्य;

	जर(!(flags & DP_F_UNSIGNED)) {
		जर( मूल्य < 0 ) {
			signvalue = '-';
			uvalue = -मूल्य;
		} अन्यथा {
			जर (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			अन्यथा जर (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	जर (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	करा {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (अचिन्हित)base  ];
		uvalue = (uvalue / (अचिन्हित)base );
	} पर्यंत(uvalue && (place < 20));
	जर (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	जर (zpadlen < 0) zpadlen = 0;
	जर (spadlen < 0) spadlen = 0;
	जर (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	जर (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	म_लिखो("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	पर्यंत (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	जर (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	जर (zpadlen > 0) {
		पर्यंत (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	पर्यंत (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	पर्यंत (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	परत 0;
}

स्थिर LDOUBLE abs_val(LDOUBLE मूल्य)
{
	LDOUBLE result = मूल्य;

	जर (मूल्य < 0)
		result = -मूल्य;

	परत result;
}

स्थिर LDOUBLE POW10(पूर्णांक val)
{
	LDOUBLE result = 1;

	पर्यंत (val) {
		result *= 10;
		val--;
	}

	परत result;
}

स्थिर LLONG ROUND(LDOUBLE मूल्य)
{
	LLONG intpart;

	intpart = (LLONG)मूल्य;
	मूल्य = मूल्य - intpart;
	जर (मूल्य >= 0.5) intpart++;

	परत intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
स्थिर द्विगुण my_modf(द्विगुण x0, द्विगुण *iptr)
{
	पूर्णांक i;
	दीर्घ l;
	द्विगुण x = x0;
	द्विगुण f = 1.0;

	साठी (i=0;i<100;i++) {
		l = (दीर्घ)x;
		जर (l <= (x+1) && l >= (x-1)) थांबा;
		x *= 0.1;
		f *= 10.0;
	}

	जर (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		परत 0;
	}

	जर (i != 0) {
		द्विगुण i2;
		द्विगुण ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		परत ret;
	}

	(*iptr) = l;
	परत x - (*iptr);
}


स्थिर पूर्णांक
fmtfp (अक्षर *buffer, माप_प्रकार *currlen, माप_प्रकार maxlen,
    LDOUBLE fvalue, पूर्णांक min, पूर्णांक max, पूर्णांक flags)
{
	पूर्णांक signvalue = 0;
	द्विगुण ufvalue;
	अक्षर iconvert[311];
	अक्षर fconvert[311];
	पूर्णांक iplace = 0;
	पूर्णांक fplace = 0;
	पूर्णांक padlen = 0; /* amount to pad */
	पूर्णांक zpadlen = 0;
#जर 0
	पूर्णांक caps = 0;
#endif
	पूर्णांक idx;
	द्विगुण intpart;
	द्विगुण fracpart;
	द्विगुण temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	जर (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	जर (fvalue < 0) {
		signvalue = '-';
	} अन्यथा {
		जर (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} अन्यथा {
			जर (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#जर 0
	जर (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#जर 0
	 जर (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	जर (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	जर (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	करा {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (पूर्णांक) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} पर्यंत (intpart && (iplace < 311));
	जर (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	जर (fracpart)
	{
		करा {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (पूर्णांक) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} पर्यंत(fracpart && (fplace < 311));
		जर (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	जर (zpadlen < 0) zpadlen = 0;
	जर (padlen < 0)
		padlen = 0;
	जर (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	जर ((flags & DP_F_ZERO) && (padlen > 0)) {
		जर (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		पर्यंत (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	पर्यंत (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	जर (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	पर्यंत (iplace > 0) {
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
	जर (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		पर्यंत (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		पर्यंत (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	पर्यंत (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	परत 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#जर !defined(HAVE_VSNPRINTF)
पूर्णांक
vsnprintf (अक्षर *str, माप_प्रकार मोजणी, स्थिरांक अक्षर *fmt, बहु_सूची args)
{
	परत dopr(str, मोजणी, fmt, args);
}
#endif

#जर !defined(HAVE_SNPRINTF)
पूर्णांक
snprintf(अक्षर *str, माप_प्रकार मोजणी, SNPRINTF_CONST अक्षर *fmt, ...)
{
	माप_प्रकार ret;
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	ret = vsnprintf(str, मोजणी, fmt, ap);
	बहु_पूर्ण(ap);
	परत ret;
}
#endif
