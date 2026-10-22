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

#समावेश "includes.h"

#अगर defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#पूर्ण_अगर

#अगर !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#समावेश <ctype.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <limits.h>
#समावेश <errno.h>

#अगर_घोषित HAVE_LONG_DOUBLE
# define LDOUBLE दीर्घ द्विगुन
#अन्यथा
# define LDOUBLE द्विगुन
#पूर्ण_अगर

#अगर_घोषित HAVE_LONG_LONG
# define LLONG दीर्घ दीर्घ
#अन्यथा
# define LLONG दीर्घ
#पूर्ण_अगर

/*
 * dopr(): poor man's version of doprintf
 */

/* format read states */
#घोषणा DP_S_DEFAULT 0
#घोषणा DP_S_FLAGS   1
#घोषणा DP_S_MIN     2
#घोषणा DP_S_DOT     3
#घोषणा DP_S_MAX     4
#घोषणा DP_S_MOD     5
#घोषणा DP_S_CONV    6
#घोषणा DP_S_DONE    7

/* format flags - Bits */
#घोषणा DP_F_MINUS	(1 << 0)
#घोषणा DP_F_PLUS	(1 << 1)
#घोषणा DP_F_SPACE	(1 << 2)
#घोषणा DP_F_अंक	(1 << 3)
#घोषणा DP_F_ZERO	(1 << 4)
#घोषणा DP_F_UP		(1 << 5)
#घोषणा DP_F_UNSIGNED	(1 << 6)

/* Conversion Flags */
#घोषणा DP_C_SHORT   1
#घोषणा DP_C_LONG    2
#घोषणा DP_C_LDOUBLE 3
#घोषणा DP_C_LLONG   4
#घोषणा DP_C_आकार    5
#घोषणा DP_C_INTMAX  6

#घोषणा char_to_int(p) ((p)- '0')
#अगर_अघोषित MAX
# define MAX(p,q) (((p) >= (q)) ? (p) : (q))
#पूर्ण_अगर

#घोषणा DOPR_OUTCH(buf, pos, buflen, thechar) \
	करो { \
		अगर (pos + 1 >= पूर्णांक_उच्च) { \
			त्रुटि_सं = दुस्फल; \
			वापस -1; \
		} \
		अगर (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} जबतक (0)

अटल पूर्णांक dopr(अक्षर *बफर, माप_प्रकार maxlen, स्थिर अक्षर *format,
    बहु_सूची args_in);
अटल पूर्णांक fmtstr(अक्षर *बफर, माप_प्रकार *currlen, माप_प्रकार maxlen,
    अक्षर *मूल्य, पूर्णांक flags, पूर्णांक min, पूर्णांक max);
अटल पूर्णांक fmtint(अक्षर *बफर, माप_प्रकार *currlen, माप_प्रकार maxlen,
    intmax_t मूल्य, पूर्णांक base, पूर्णांक min, पूर्णांक max, पूर्णांक flags);
अटल पूर्णांक fmtfp(अक्षर *बफर, माप_प्रकार *currlen, माप_प्रकार maxlen,
    LDOUBLE fvalue, पूर्णांक min, पूर्णांक max, पूर्णांक flags);

अटल पूर्णांक
dopr(अक्षर *बफर, माप_प्रकार maxlen, स्थिर अक्षर *format, बहु_सूची args_in)
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

	जबतक (state != DP_S_DONE) {
		अगर (ch == '\0')
			state = DP_S_DONE;

		चयन(state) {
		हाल DP_S_DEFAULT:
			अगर (ch == '%')
				state = DP_S_FLAGS;
			अन्यथा
				DOPR_OUTCH(बफर, currlen, maxlen, ch);
			ch = *format++;
			अवरोध;
		हाल DP_S_FLAGS:
			चयन (ch) {
			हाल '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				अवरोध;
			हाल '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				अवरोध;
			हाल ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				अवरोध;
			हाल '#':
				flags |= DP_F_अंक;
				ch = *format++;
				अवरोध;
			हाल '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				अवरोध;
			शेष:
				state = DP_S_MIN;
				अवरोध;
			}
			अवरोध;
		हाल DP_S_MIN:
			अगर (है_अंक((अचिन्हित अक्षर)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} अन्यथा अगर (ch == '*') {
				min = बहु_तर्क (args, पूर्णांक);
				ch = *format++;
				state = DP_S_DOT;
			} अन्यथा {
				state = DP_S_DOT;
			}
			अवरोध;
		हाल DP_S_DOT:
			अगर (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} अन्यथा {
				state = DP_S_MOD;
			}
			अवरोध;
		हाल DP_S_MAX:
			अगर (है_अंक((अचिन्हित अक्षर)ch)) {
				अगर (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} अन्यथा अगर (ch == '*') {
				max = बहु_तर्क (args, पूर्णांक);
				ch = *format++;
				state = DP_S_MOD;
			} अन्यथा {
				state = DP_S_MOD;
			}
			अवरोध;
		हाल DP_S_MOD:
			चयन (ch) {
			हाल 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				अवरोध;
			हाल 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				अवरोध;
			हाल 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				अगर (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				अवरोध;
			हाल 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				अवरोध;
			हाल 'z':
				cflags = DP_C_आकार;
				ch = *format++;
				अवरोध;
			शेष:
				अवरोध;
			}
			state = DP_S_CONV;
			अवरोध;
		हाल DP_S_CONV:
			चयन (ch) {
			हाल 'd':
			हाल 'i':
				अगर (cflags == DP_C_SHORT)
					मूल्य = बहु_तर्क (args, पूर्णांक);
				अन्यथा अगर (cflags == DP_C_LONG)
					मूल्य = बहु_तर्क (args, दीर्घ पूर्णांक);
				अन्यथा अगर (cflags == DP_C_LLONG)
					मूल्य = बहु_तर्क (args, LLONG);
				अन्यथा अगर (cflags == DP_C_आकार)
					मूल्य = बहु_तर्क (args, ssize_t);
				अन्यथा अगर (cflags == DP_C_INTMAX)
					मूल्य = बहु_तर्क (args, intmax_t);
				अन्यथा
					मूल्य = बहु_तर्क (args, पूर्णांक);
				अगर (fmtint(बफर, &currlen, maxlen,
				    मूल्य, 10, min, max, flags) == -1)
					जाओ fail;
				अवरोध;
			हाल 'o':
				flags |= DP_F_UNSIGNED;
				अगर (cflags == DP_C_SHORT)
					मूल्य = बहु_तर्क (args, अचिन्हित पूर्णांक);
				अन्यथा अगर (cflags == DP_C_LONG)
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित दीर्घ पूर्णांक);
				अन्यथा अगर (cflags == DP_C_LLONG)
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित LLONG);
				अन्यथा अगर (cflags == DP_C_आकार)
					मूल्य = बहु_तर्क (args, माप_प्रकार);
#अगर_घोषित notyet
				अन्यथा अगर (cflags == DP_C_INTMAX)
					मूल्य = बहु_तर्क (args, uintmax_t);
#पूर्ण_अगर
				अन्यथा
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित पूर्णांक);
				अगर (fmtint(बफर, &currlen, maxlen, मूल्य,
				    8, min, max, flags) == -1)
					जाओ fail;
				अवरोध;
			हाल 'u':
				flags |= DP_F_UNSIGNED;
				अगर (cflags == DP_C_SHORT)
					मूल्य = बहु_तर्क (args, अचिन्हित पूर्णांक);
				अन्यथा अगर (cflags == DP_C_LONG)
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित दीर्घ पूर्णांक);
				अन्यथा अगर (cflags == DP_C_LLONG)
					मूल्य = (LLONG)बहु_तर्क (args, अचिन्हित LLONG);
				अन्यथा अगर (cflags == DP_C_आकार)
					मूल्य = बहु_तर्क (args, माप_प्रकार);
#अगर_घोषित notyet
				अन्यथा अगर (cflags == DP_C_INTMAX)
					मूल्य = बहु_तर्क (args, uintmax_t);
#पूर्ण_अगर
				अन्यथा
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित पूर्णांक);
				अगर (fmtint(बफर, &currlen, maxlen, मूल्य,
				    10, min, max, flags) == -1)
					जाओ fail;
				अवरोध;
			हाल 'X':
				flags |= DP_F_UP;
			हाल 'x':
				flags |= DP_F_UNSIGNED;
				अगर (cflags == DP_C_SHORT)
					मूल्य = बहु_तर्क (args, अचिन्हित पूर्णांक);
				अन्यथा अगर (cflags == DP_C_LONG)
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित दीर्घ पूर्णांक);
				अन्यथा अगर (cflags == DP_C_LLONG)
					मूल्य = (LLONG)बहु_तर्क (args, अचिन्हित LLONG);
				अन्यथा अगर (cflags == DP_C_आकार)
					मूल्य = बहु_तर्क (args, माप_प्रकार);
#अगर_घोषित notyet
				अन्यथा अगर (cflags == DP_C_INTMAX)
					मूल्य = बहु_तर्क (args, uintmax_t);
#पूर्ण_अगर
				अन्यथा
					मूल्य = (दीर्घ)बहु_तर्क (args, अचिन्हित पूर्णांक);
				अगर (fmtint(बफर, &currlen, maxlen, मूल्य,
				    16, min, max, flags) == -1)
					जाओ fail;
				अवरोध;
			हाल 'f':
				अगर (cflags == DP_C_LDOUBLE)
					fvalue = बहु_तर्क (args, LDOUBLE);
				अन्यथा
					fvalue = बहु_तर्क (args, द्विगुन);
				अगर (fmtfp(बफर, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					जाओ fail;
				अवरोध;
			हाल 'E':
				flags |= DP_F_UP;
			हाल 'e':
				अगर (cflags == DP_C_LDOUBLE)
					fvalue = बहु_तर्क (args, LDOUBLE);
				अन्यथा
					fvalue = बहु_तर्क (args, द्विगुन);
				अगर (fmtfp(बफर, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					जाओ fail;
				अवरोध;
			हाल 'G':
				flags |= DP_F_UP;
			हाल 'g':
				अगर (cflags == DP_C_LDOUBLE)
					fvalue = बहु_तर्क (args, LDOUBLE);
				अन्यथा
					fvalue = बहु_तर्क (args, द्विगुन);
				अगर (fmtfp(बफर, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					जाओ fail;
				अवरोध;
			हाल 'c':
				DOPR_OUTCH(बफर, currlen, maxlen,
				    बहु_तर्क (args, पूर्णांक));
				अवरोध;
			हाल 's':
				strvalue = बहु_तर्क (args, अक्षर *);
				अगर (!strvalue) strvalue = "(NULL)";
				अगर (max == -1) {
					max = म_माप(strvalue);
				}
				अगर (min > 0 && max >= 0 && min > max) max = min;
				अगर (fmtstr(बफर, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					जाओ fail;
				अवरोध;
			हाल 'p':
				strvalue = बहु_तर्क (args, व्योम *);
				अगर (fmtint(बफर, &currlen, maxlen,
				    (दीर्घ) strvalue, 16, min, max, flags) == -1)
					जाओ fail;
				अवरोध;
#अगर we_dont_want_this_in_openssh
			हाल 'n':
				अगर (cflags == DP_C_SHORT) {
					लघु पूर्णांक *अंक;
					अंक = बहु_तर्क (args, लघु पूर्णांक *);
					*अंक = currlen;
				} अन्यथा अगर (cflags == DP_C_LONG) {
					दीर्घ पूर्णांक *अंक;
					अंक = बहु_तर्क (args, दीर्घ पूर्णांक *);
					*अंक = (दीर्घ पूर्णांक)currlen;
				} अन्यथा अगर (cflags == DP_C_LLONG) {
					LLONG *अंक;
					अंक = बहु_तर्क (args, LLONG *);
					*अंक = (LLONG)currlen;
				} अन्यथा अगर (cflags == DP_C_आकार) {
					ssize_t *अंक;
					अंक = बहु_तर्क (args, ssize_t *);
					*अंक = (ssize_t)currlen;
				} अन्यथा अगर (cflags == DP_C_INTMAX) {
					intmax_t *अंक;
					अंक = बहु_तर्क (args, intmax_t *);
					*अंक = (intmax_t)currlen;
				} अन्यथा {
					पूर्णांक *अंक;
					अंक = बहु_तर्क (args, पूर्णांक *);
					*अंक = currlen;
				}
				अवरोध;
#पूर्ण_अगर
			हाल '%':
				DOPR_OUTCH(बफर, currlen, maxlen, ch);
				अवरोध;
			शेष:
				/* Unknown, skip */
				अवरोध;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			अवरोध;
		हाल DP_S_DONE:
			अवरोध;
		शेष:
			/* hmm? */
			अवरोध; /* some picky compilers need this */
		}
	}
	अगर (maxlen != 0) {
		अगर (currlen < maxlen - 1)
			बफर[currlen] = '\0';
		अन्यथा अगर (maxlen > 0)
			बफर[maxlen - 1] = '\0';
	}
	बहु_पूर्ण(args);
	वापस currlen < पूर्णांक_उच्च ? (पूर्णांक)currlen : -1;
 fail:
	बहु_पूर्ण(args);
	वापस -1;
}

अटल पूर्णांक
fmtstr(अक्षर *बफर, माप_प्रकार *currlen, माप_प्रकार maxlen,
    अक्षर *मूल्य, पूर्णांक flags, पूर्णांक min, पूर्णांक max)
{
	पूर्णांक padlen, strln;     /* amount to pad */
	पूर्णांक cnt = 0;

#अगर_घोषित DEBUG_SNPRINTF
	म_लिखो("fmtstr min=%d max=%d s=[%s]\n", min, max, मूल्य);
#पूर्ण_अगर
	अगर (मूल्य == 0) {
		मूल्य = "<NULL>";
	}

	क्रम (strln = 0; strln < max && मूल्य[strln]; ++strln); /* strlen */
	padlen = min - strln;
	अगर (padlen < 0)
		padlen = 0;
	अगर (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	जबतक ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(बफर, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	जबतक (*मूल्य && (cnt < max)) {
		DOPR_OUTCH(बफर, *currlen, maxlen, *मूल्य);
		मूल्य++;
		++cnt;
	}
	जबतक ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(बफर, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	वापस 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

अटल पूर्णांक
fmtint(अक्षर *बफर, माप_प्रकार *currlen, माप_प्रकार maxlen,
    intmax_t मूल्य, पूर्णांक base, पूर्णांक min, पूर्णांक max, पूर्णांक flags)
{
	पूर्णांक signvalue = 0;
	अचिन्हित LLONG uvalue;
	अक्षर convert[20];
	पूर्णांक place = 0;
	पूर्णांक spadlen = 0; /* amount to space pad */
	पूर्णांक zpadlen = 0; /* amount to zero pad */
	पूर्णांक caps = 0;

	अगर (max < 0)
		max = 0;

	uvalue = मूल्य;

	अगर(!(flags & DP_F_UNSIGNED)) {
		अगर( मूल्य < 0 ) {
			signvalue = '-';
			uvalue = -मूल्य;
		} अन्यथा {
			अगर (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			अन्यथा अगर (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	अगर (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	करो {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (अचिन्हित)base  ];
		uvalue = (uvalue / (अचिन्हित)base );
	} जबतक(uvalue && (place < 20));
	अगर (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	अगर (zpadlen < 0) zpadlen = 0;
	अगर (spadlen < 0) spadlen = 0;
	अगर (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	अगर (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#अगर_घोषित DEBUG_SNPRINTF
	म_लिखो("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#पूर्ण_अगर

	/* Spaces */
	जबतक (spadlen > 0) {
		DOPR_OUTCH(बफर, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	अगर (signvalue)
		DOPR_OUTCH(बफर, *currlen, maxlen, signvalue);

	/* Zeros */
	अगर (zpadlen > 0) {
		जबतक (zpadlen > 0) {
			DOPR_OUTCH(बफर, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	जबतक (place > 0) {
		--place;
		DOPR_OUTCH(बफर, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	जबतक (spadlen < 0) {
		DOPR_OUTCH(बफर, *currlen, maxlen, ' ');
		++spadlen;
	}
	वापस 0;
}

अटल LDOUBLE abs_val(LDOUBLE मूल्य)
{
	LDOUBLE परिणाम = मूल्य;

	अगर (मूल्य < 0)
		परिणाम = -मूल्य;

	वापस परिणाम;
}

अटल LDOUBLE POW10(पूर्णांक val)
{
	LDOUBLE परिणाम = 1;

	जबतक (val) {
		परिणाम *= 10;
		val--;
	}

	वापस परिणाम;
}

अटल LLONG ROUND(LDOUBLE मूल्य)
{
	LLONG intpart;

	intpart = (LLONG)मूल्य;
	मूल्य = मूल्य - intpart;
	अगर (मूल्य >= 0.5) intpart++;

	वापस intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
अटल द्विगुन my_modf(द्विगुन x0, द्विगुन *iptr)
{
	पूर्णांक i;
	दीर्घ l;
	द्विगुन x = x0;
	द्विगुन f = 1.0;

	क्रम (i=0;i<100;i++) {
		l = (दीर्घ)x;
		अगर (l <= (x+1) && l >= (x-1)) अवरोध;
		x *= 0.1;
		f *= 10.0;
	}

	अगर (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		वापस 0;
	}

	अगर (i != 0) {
		द्विगुन i2;
		द्विगुन ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		वापस ret;
	}

	(*iptr) = l;
	वापस x - (*iptr);
}


अटल पूर्णांक
fmtfp (अक्षर *बफर, माप_प्रकार *currlen, माप_प्रकार maxlen,
    LDOUBLE fvalue, पूर्णांक min, पूर्णांक max, पूर्णांक flags)
{
	पूर्णांक signvalue = 0;
	द्विगुन ufvalue;
	अक्षर iconvert[311];
	अक्षर fconvert[311];
	पूर्णांक iplace = 0;
	पूर्णांक fplace = 0;
	पूर्णांक padlen = 0; /* amount to pad */
	पूर्णांक zpadlen = 0;
#अगर 0
	पूर्णांक caps = 0;
#पूर्ण_अगर
	पूर्णांक idx;
	द्विगुन intpart;
	द्विगुन fracpart;
	द्विगुन अस्थायी;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	अगर (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	अगर (fvalue < 0) {
		signvalue = '-';
	} अन्यथा {
		अगर (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} अन्यथा {
			अगर (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#अगर 0
	अगर (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#पूर्ण_अगर

#अगर 0
	 अगर (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#पूर्ण_अगर

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	अगर (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	अस्थायी = ufvalue;
	my_modf(अस्थायी, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	अगर (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	करो {
		अस्थायी = intpart*0.1;
		my_modf(अस्थायी, &intpart);
		idx = (पूर्णांक) ((अस्थायी -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} जबतक (intpart && (iplace < 311));
	अगर (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	अगर (fracpart)
	{
		करो {
			अस्थायी = fracpart*0.1;
			my_modf(अस्थायी, &fracpart);
			idx = (पूर्णांक) ((अस्थायी -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} जबतक(fracpart && (fplace < 311));
		अगर (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	अगर (zpadlen < 0) zpadlen = 0;
	अगर (padlen < 0)
		padlen = 0;
	अगर (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	अगर ((flags & DP_F_ZERO) && (padlen > 0)) {
		अगर (signvalue) {
			DOPR_OUTCH(बफर, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		जबतक (padlen > 0) {
			DOPR_OUTCH(बफर, *currlen, maxlen, '0');
			--padlen;
		}
	}
	जबतक (padlen > 0) {
		DOPR_OUTCH(बफर, *currlen, maxlen, ' ');
		--padlen;
	}
	अगर (signvalue)
		DOPR_OUTCH(बफर, *currlen, maxlen, signvalue);

	जबतक (iplace > 0) {
		--iplace;
		DOPR_OUTCH(बफर, *currlen, maxlen, iconvert[iplace]);
	}

#अगर_घोषित DEBUG_SNPRINTF
	म_लिखो("fmtfp: fplace=%d zpadlen=%d\n", fplace, zpadlen);
#पूर्ण_अगर

	/*
	 * Decimal point.  This should probably use locale to find the correct
	 * char to print out.
	 */
	अगर (max > 0) {
		DOPR_OUTCH(बफर, *currlen, maxlen, '.');

		जबतक (zpadlen > 0) {
			DOPR_OUTCH(बफर, *currlen, maxlen, '0');
			--zpadlen;
		}

		जबतक (fplace > 0) {
			--fplace;
			DOPR_OUTCH(बफर, *currlen, maxlen, fconvert[fplace]);
		}
	}

	जबतक (padlen < 0) {
		DOPR_OUTCH(बफर, *currlen, maxlen, ' ');
		++padlen;
	}
	वापस 0;
}
#पूर्ण_अगर /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#अगर !defined(HAVE_VSNPRINTF)
पूर्णांक
vsnprintf (अक्षर *str, माप_प्रकार गिनती, स्थिर अक्षर *fmt, बहु_सूची args)
{
	वापस dopr(str, गिनती, fmt, args);
}
#पूर्ण_अगर

#अगर !defined(HAVE_SNPRINTF)
पूर्णांक
snprintf(अक्षर *str, माप_प्रकार गिनती, SNPRINTF_CONST अक्षर *fmt, ...)
{
	माप_प्रकार ret;
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	ret = vsnprintf(str, गिनती, fmt, ap);
	बहु_पूर्ण(ap);
	वापस ret;
}
#पूर्ण_अगर
