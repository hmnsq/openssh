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

#అన్తర్భావ "includes.h"

#ఒకవేళ defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <errno.h>

#నిర్వచితమైతే HAVE_LONG_DOUBLE
# define LDOUBLE దీర్ఘ ద్విగుణ
#లేకపోతే
# define LDOUBLE ద్విగుణ
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_LONG_LONG
# define LLONG దీర్ఘ దీర్ఘ
#లేకపోతే
# define LLONG దీర్ఘ
#అయితే_ముగింపు

/*
 * dopr(): poor man's version of doprintf
 */

/* format read states */
#నిర్వచించు DP_S_DEFAULT 0
#నిర్వచించు DP_S_FLAGS   1
#నిర్వచించు DP_S_MIN     2
#నిర్వచించు DP_S_DOT     3
#నిర్వచించు DP_S_MAX     4
#నిర్వచించు DP_S_MOD     5
#నిర్వచించు DP_S_CONV    6
#నిర్వచించు DP_S_పూర్తి    7

/* format flags - Bits */
#నిర్వచించు DP_F_MINUS	(1 << 0)
#నిర్వచించు DP_F_PLUS	(1 << 1)
#నిర్వచించు DP_F_SPACE	(1 << 2)
#నిర్వచించు DP_F_అంకె	(1 << 3)
#నిర్వచించు DP_F_ZERO	(1 << 4)
#నిర్వచించు DP_F_పైకి		(1 << 5)
#నిర్వచించు DP_F_UNSIGNED	(1 << 6)

/* Conversion Flags */
#నిర్వచించు DP_C_SHORT   1
#నిర్వచించు DP_C_LONG    2
#నిర్వచించు DP_C_LDOUBLE 3
#నిర్వచించు DP_C_LLONG   4
#నిర్వచించు DP_C_కొలత    5
#నిర్వచించు DP_C_INTMAX  6

#నిర్వచించు char_గమ్యం_int(p) ((p)- '0')
#నిర్వచితం_కాకపోతే MAX
# define MAX(p,q) (((p) >= (q)) ? (p) : (q))
#అయితే_ముగింపు

#నిర్వచించు DOPR_OUTCH(buf, pos, buflen, thechar) \
	చేయి { \
		ఒకవేళ (pos + 1 >= గరిష్ఠ_పూర్ణాంకం) { \
			errno = ERANGE; \
			తిరిగి -1; \
		} \
		ఒకవేళ (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} అయితే (0)

స్థిర పూర్ణాంకం dopr(అక్షరం *బఫరు, కొలత_t maxlen, స్థిరరాశి అక్షరం *format,
    va_list వాదనలు_లోపల);
స్థిర పూర్ణాంకం fmtstr(అక్షరం *బఫరు, కొలత_t *currlen, కొలత_t maxlen,
    అక్షరం *విలువ, పూర్ణాంకం flags, పూర్ణాంకం min, పూర్ణాంకం max);
స్థిర పూర్ణాంకం fmtint(అక్షరం *బఫరు, కొలత_t *currlen, కొలత_t maxlen,
    intmax_t విలువ, పూర్ణాంకం పునాది, పూర్ణాంకం min, పూర్ణాంకం max, పూర్ణాంకం flags);
స్థిర పూర్ణాంకం fmtfp(అక్షరం *బఫరు, కొలత_t *currlen, కొలత_t maxlen,
    LDOUBLE fvalue, పూర్ణాంకం min, పూర్ణాంకం max, పూర్ణాంకం flags);

స్థిర పూర్ణాంకం
dopr(అక్షరం *బఫరు, కొలత_t maxlen, స్థిరరాశి అక్షరం *format, va_list వాదనలు_లోపల)
{
	అక్షరం ch;
	intmax_t విలువ;
	LDOUBLE fvalue;
	అక్షరం *strvalue;
	పూర్ణాంకం min;
	పూర్ణాంకం max;
	పూర్ణాంకం state;
	పూర్ణాంకం flags;
	పూర్ణాంకం cflags;
	కొలత_t currlen;
	va_list వాదనలు;

	VA_COPY(వాదనలు, వాదనలు_లోపల);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	అయితే (state != DP_S_పూర్తి) {
		ఒకవేళ (ch == '\0')
			state = DP_S_పూర్తి;

		ఎంపిక(state) {
		స్థితి DP_S_DEFAULT:
			ఒకవేళ (ch == '%')
				state = DP_S_FLAGS;
			లేకపోతే
				DOPR_OUTCH(బఫరు, currlen, maxlen, ch);
			ch = *format++;
			ఆపు;
		స్థితి DP_S_FLAGS:
			ఎంపిక (ch) {
			స్థితి '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				ఆపు;
			స్థితి '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				ఆపు;
			స్థితి ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				ఆపు;
			స్థితి '#':
				flags |= DP_F_అంకె;
				ch = *format++;
				ఆపు;
			స్థితి '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				ఆపు;
			అప్రమేయ:
				state = DP_S_MIN;
				ఆపు;
			}
			ఆపు;
		స్థితి DP_S_MIN:
			ఒకవేళ (అంకెనా((గుర్తులేని అక్షరం)ch)) {
				min = 10*min + char_గమ్యం_int (ch);
				ch = *format++;
			} లేకపోతే ఒకవేళ (ch == '*') {
				min = va_arg (వాదనలు, పూర్ణాంకం);
				ch = *format++;
				state = DP_S_DOT;
			} లేకపోతే {
				state = DP_S_DOT;
			}
			ఆపు;
		స్థితి DP_S_DOT:
			ఒకవేళ (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} లేకపోతే {
				state = DP_S_MOD;
			}
			ఆపు;
		స్థితి DP_S_MAX:
			ఒకవేళ (అంకెనా((గుర్తులేని అక్షరం)ch)) {
				ఒకవేళ (max < 0)
					max = 0;
				max = 10*max + char_గమ్యం_int (ch);
				ch = *format++;
			} లేకపోతే ఒకవేళ (ch == '*') {
				max = va_arg (వాదనలు, పూర్ణాంకం);
				ch = *format++;
				state = DP_S_MOD;
			} లేకపోతే {
				state = DP_S_MOD;
			}
			ఆపు;
		స్థితి DP_S_MOD:
			ఎంపిక (ch) {
			స్థితి 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				ఆపు;
			స్థితి 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				ఆపు;
			స్థితి 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				ఒకవేళ (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				ఆపు;
			స్థితి 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				ఆపు;
			స్థితి 'z':
				cflags = DP_C_కొలత;
				ch = *format++;
				ఆపు;
			అప్రమేయ:
				ఆపు;
			}
			state = DP_S_CONV;
			ఆపు;
		స్థితి DP_S_CONV:
			ఎంపిక (ch) {
			స్థితి 'd':
			స్థితి 'i':
				ఒకవేళ (cflags == DP_C_SHORT)
					విలువ = va_arg (వాదనలు, పూర్ణాంకం);
				లేకపోతే ఒకవేళ (cflags == DP_C_LONG)
					విలువ = va_arg (వాదనలు, దీర్ఘ పూర్ణాంకం);
				లేకపోతే ఒకవేళ (cflags == DP_C_LLONG)
					విలువ = va_arg (వాదనలు, LLONG);
				లేకపోతే ఒకవేళ (cflags == DP_C_కొలత)
					విలువ = va_arg (వాదనలు, ssize_t);
				లేకపోతే ఒకవేళ (cflags == DP_C_INTMAX)
					విలువ = va_arg (వాదనలు, intmax_t);
				లేకపోతే
					విలువ = va_arg (వాదనలు, పూర్ణాంకం);
				ఒకవేళ (fmtint(బఫరు, &currlen, maxlen,
				    విలువ, 10, min, max, flags) == -1)
					వెళ్ళు fail;
				ఆపు;
			స్థితి 'o':
				flags |= DP_F_UNSIGNED;
				ఒకవేళ (cflags == DP_C_SHORT)
					విలువ = va_arg (వాదనలు, గుర్తులేని పూర్ణాంకం);
				లేకపోతే ఒకవేళ (cflags == DP_C_LONG)
					విలువ = (దీర్ఘ)va_arg (వాదనలు, గుర్తులేని దీర్ఘ పూర్ణాంకం);
				లేకపోతే ఒకవేళ (cflags == DP_C_LLONG)
					విలువ = (దీర్ఘ)va_arg (వాదనలు, గుర్తులేని LLONG);
				లేకపోతే ఒకవేళ (cflags == DP_C_కొలత)
					విలువ = va_arg (వాదనలు, కొలత_t);
#నిర్వచితమైతే notyet
				లేకపోతే ఒకవేళ (cflags == DP_C_INTMAX)
					విలువ = va_arg (వాదనలు, uintmax_t);
#అయితే_ముగింపు
				లేకపోతే
					విలువ = (దీర్ఘ)va_arg (వాదనలు, గుర్తులేని పూర్ణాంకం);
				ఒకవేళ (fmtint(బఫరు, &currlen, maxlen, విలువ,
				    8, min, max, flags) == -1)
					వెళ్ళు fail;
				ఆపు;
			స్థితి 'u':
				flags |= DP_F_UNSIGNED;
				ఒకవేళ (cflags == DP_C_SHORT)
					విలువ = va_arg (వాదనలు, గుర్తులేని పూర్ణాంకం);
				లేకపోతే ఒకవేళ (cflags == DP_C_LONG)
					విలువ = (దీర్ఘ)va_arg (వాదనలు, గుర్తులేని దీర్ఘ పూర్ణాంకం);
				లేకపోతే ఒకవేళ (cflags == DP_C_LLONG)
					విలువ = (LLONG)va_arg (వాదనలు, గుర్తులేని LLONG);
				లేకపోతే ఒకవేళ (cflags == DP_C_కొలత)
					విలువ = va_arg (వాదనలు, కొలత_t);
#నిర్వచితమైతే notyet
				లేకపోతే ఒకవేళ (cflags == DP_C_INTMAX)
					విలువ = va_arg (వాదనలు, uintmax_t);
#అయితే_ముగింపు
				లేకపోతే
					విలువ = (దీర్ఘ)va_arg (వాదనలు, గుర్తులేని పూర్ణాంకం);
				ఒకవేళ (fmtint(బఫరు, &currlen, maxlen, విలువ,
				    10, min, max, flags) == -1)
					వెళ్ళు fail;
				ఆపు;
			స్థితి 'X':
				flags |= DP_F_పైకి;
			స్థితి 'x':
				flags |= DP_F_UNSIGNED;
				ఒకవేళ (cflags == DP_C_SHORT)
					విలువ = va_arg (వాదనలు, గుర్తులేని పూర్ణాంకం);
				లేకపోతే ఒకవేళ (cflags == DP_C_LONG)
					విలువ = (దీర్ఘ)va_arg (వాదనలు, గుర్తులేని దీర్ఘ పూర్ణాంకం);
				లేకపోతే ఒకవేళ (cflags == DP_C_LLONG)
					విలువ = (LLONG)va_arg (వాదనలు, గుర్తులేని LLONG);
				లేకపోతే ఒకవేళ (cflags == DP_C_కొలత)
					విలువ = va_arg (వాదనలు, కొలత_t);
#నిర్వచితమైతే notyet
				లేకపోతే ఒకవేళ (cflags == DP_C_INTMAX)
					విలువ = va_arg (వాదనలు, uintmax_t);
#అయితే_ముగింపు
				లేకపోతే
					విలువ = (దీర్ఘ)va_arg (వాదనలు, గుర్తులేని పూర్ణాంకం);
				ఒకవేళ (fmtint(బఫరు, &currlen, maxlen, విలువ,
				    16, min, max, flags) == -1)
					వెళ్ళు fail;
				ఆపు;
			స్థితి 'f':
				ఒకవేళ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (వాదనలు, LDOUBLE);
				లేకపోతే
					fvalue = va_arg (వాదనలు, ద్విగుణ);
				ఒకవేళ (fmtfp(బఫరు, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					వెళ్ళు fail;
				ఆపు;
			స్థితి 'E':
				flags |= DP_F_పైకి;
			స్థితి 'e':
				ఒకవేళ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (వాదనలు, LDOUBLE);
				లేకపోతే
					fvalue = va_arg (వాదనలు, ద్విగుణ);
				ఒకవేళ (fmtfp(బఫరు, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					వెళ్ళు fail;
				ఆపు;
			స్థితి 'G':
				flags |= DP_F_పైకి;
			స్థితి 'g':
				ఒకవేళ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (వాదనలు, LDOUBLE);
				లేకపోతే
					fvalue = va_arg (వాదనలు, ద్విగుణ);
				ఒకవేళ (fmtfp(బఫరు, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					వెళ్ళు fail;
				ఆపు;
			స్థితి 'c':
				DOPR_OUTCH(బఫరు, currlen, maxlen,
				    va_arg (వాదనలు, పూర్ణాంకం));
				ఆపు;
			స్థితి 's':
				strvalue = va_arg (వాదనలు, అక్షరం *);
				ఒకవేళ (!strvalue) strvalue = "(NULL)";
				ఒకవేళ (max == -1) {
					max = అక్షరశ్రేణి_పొడవు(strvalue);
				}
				ఒకవేళ (min > 0 && max >= 0 && min > max) max = min;
				ఒకవేళ (fmtstr(బఫరు, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					వెళ్ళు fail;
				ఆపు;
			స్థితి 'p':
				strvalue = va_arg (వాదనలు, శూన్య *);
				ఒకవేళ (fmtint(బఫరు, &currlen, maxlen,
				    (దీర్ఘ) strvalue, 16, min, max, flags) == -1)
					వెళ్ళు fail;
				ఆపు;
#ఒకవేళ we_dont_want_this_లోపల_openssh
			స్థితి 'n':
				ఒకవేళ (cflags == DP_C_SHORT) {
					పొట్టి పూర్ణాంకం *అంకె;
					అంకె = va_arg (వాదనలు, పొట్టి పూర్ణాంకం *);
					*అంకె = currlen;
				} లేకపోతే ఒకవేళ (cflags == DP_C_LONG) {
					దీర్ఘ పూర్ణాంకం *అంకె;
					అంకె = va_arg (వాదనలు, దీర్ఘ పూర్ణాంకం *);
					*అంకె = (దీర్ఘ పూర్ణాంకం)currlen;
				} లేకపోతే ఒకవేళ (cflags == DP_C_LLONG) {
					LLONG *అంకె;
					అంకె = va_arg (వాదనలు, LLONG *);
					*అంకె = (LLONG)currlen;
				} లేకపోతే ఒకవేళ (cflags == DP_C_కొలత) {
					ssize_t *అంకె;
					అంకె = va_arg (వాదనలు, ssize_t *);
					*అంకె = (ssize_t)currlen;
				} లేకపోతే ఒకవేళ (cflags == DP_C_INTMAX) {
					intmax_t *అంకె;
					అంకె = va_arg (వాదనలు, intmax_t *);
					*అంకె = (intmax_t)currlen;
				} లేకపోతే {
					పూర్ణాంకం *అంకె;
					అంకె = va_arg (వాదనలు, పూర్ణాంకం *);
					*అంకె = currlen;
				}
				ఆపు;
#అయితే_ముగింపు
			స్థితి '%':
				DOPR_OUTCH(బఫరు, currlen, maxlen, ch);
				ఆపు;
			అప్రమేయ:
				/* Unknown, skip */
				ఆపు;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			ఆపు;
		స్థితి DP_S_పూర్తి:
			ఆపు;
		అప్రమేయ:
			/* hmm? */
			ఆపు; /* some picky compilers need this */
		}
	}
	ఒకవేళ (maxlen != 0) {
		ఒకవేళ (currlen < maxlen - 1)
			బఫరు[currlen] = '\0';
		లేకపోతే ఒకవేళ (maxlen > 0)
			బఫరు[maxlen - 1] = '\0';
	}
	va_end(వాదనలు);
	తిరిగి currlen < గరిష్ఠ_పూర్ణాంకం ? (పూర్ణాంకం)currlen : -1;
 fail:
	va_end(వాదనలు);
	తిరిగి -1;
}

స్థిర పూర్ణాంకం
fmtstr(అక్షరం *బఫరు, కొలత_t *currlen, కొలత_t maxlen,
    అక్షరం *విలువ, పూర్ణాంకం flags, పూర్ణాంకం min, పూర్ణాంకం max)
{
	పూర్ణాంకం padlen, strln;     /* amount to pad */
	పూర్ణాంకం cnt = 0;

#నిర్వచితమైతే DEBUG_SNPRINTF
	రాయి("fmtstr min=%d max=%d s=[%s]\n", min, max, విలువ);
#అయితే_ముగింపు
	ఒకవేళ (విలువ == 0) {
		విలువ = "<NULL>";
	}

	కొరకు (strln = 0; strln < max && విలువ[strln]; ++strln); /* strlen */
	padlen = min - strln;
	ఒకవేళ (padlen < 0)
		padlen = 0;
	ఒకవేళ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	అయితే ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(బఫరు, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	అయితే (*విలువ && (cnt < max)) {
		DOPR_OUTCH(బఫరు, *currlen, maxlen, *విలువ);
		విలువ++;
		++cnt;
	}
	అయితే ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(బఫరు, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	తిరిగి 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

స్థిర పూర్ణాంకం
fmtint(అక్షరం *బఫరు, కొలత_t *currlen, కొలత_t maxlen,
    intmax_t విలువ, పూర్ణాంకం పునాది, పూర్ణాంకం min, పూర్ణాంకం max, పూర్ణాంకం flags)
{
	పూర్ణాంకం signvalue = 0;
	గుర్తులేని LLONG uvalue;
	అక్షరం convert[20];
	పూర్ణాంకం ఉంచు = 0;
	పూర్ణాంకం spadlen = 0; /* amount to space pad */
	పూర్ణాంకం zpadlen = 0; /* amount to zero pad */
	పూర్ణాంకం caps = 0;

	ఒకవేళ (max < 0)
		max = 0;

	uvalue = విలువ;

	ఒకవేళ(!(flags & DP_F_UNSIGNED)) {
		ఒకవేళ( విలువ < 0 ) {
			signvalue = '-';
			uvalue = -విలువ;
		} లేకపోతే {
			ఒకవేళ (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			లేకపోతే ఒకవేళ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	ఒకవేళ (flags & DP_F_పైకి) caps = 1; /* Should characters be upper case? */

	చేయి {
		convert[ఉంచు++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (గుర్తులేని)పునాది  ];
		uvalue = (uvalue / (గుర్తులేని)పునాది );
	} అయితే(uvalue && (ఉంచు < 20));
	ఒకవేళ (ఉంచు == 20) ఉంచు--;
	convert[ఉంచు] = 0;

	zpadlen = max - ఉంచు;
	spadlen = min - MAX (max, ఉంచు) - (signvalue ? 1 : 0);
	ఒకవేళ (zpadlen < 0) zpadlen = 0;
	ఒకవేళ (spadlen < 0) spadlen = 0;
	ఒకవేళ (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	ఒకవేళ (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#నిర్వచితమైతే DEBUG_SNPRINTF
	రాయి("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, ఉంచు);
#అయితే_ముగింపు

	/* Spaces */
	అయితే (spadlen > 0) {
		DOPR_OUTCH(బఫరు, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	ఒకవేళ (signvalue)
		DOPR_OUTCH(బఫరు, *currlen, maxlen, signvalue);

	/* Zeros */
	ఒకవేళ (zpadlen > 0) {
		అయితే (zpadlen > 0) {
			DOPR_OUTCH(బఫరు, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	అయితే (ఉంచు > 0) {
		--ఉంచు;
		DOPR_OUTCH(బఫరు, *currlen, maxlen, convert[ఉంచు]);
	}

	/* Left Justified spaces */
	అయితే (spadlen < 0) {
		DOPR_OUTCH(బఫరు, *currlen, maxlen, ' ');
		++spadlen;
	}
	తిరిగి 0;
}

స్థిర LDOUBLE abs_val(LDOUBLE విలువ)
{
	LDOUBLE ఫలితం = విలువ;

	ఒకవేళ (విలువ < 0)
		ఫలితం = -విలువ;

	తిరిగి ఫలితం;
}

స్థిర LDOUBLE POW10(పూర్ణాంకం val)
{
	LDOUBLE ఫలితం = 1;

	అయితే (val) {
		ఫలితం *= 10;
		val--;
	}

	తిరిగి ఫలితం;
}

స్థిర LLONG విడత_2(LDOUBLE విలువ)
{
	LLONG intpart;

	intpart = (LLONG)విలువ;
	విలువ = విలువ - intpart;
	ఒకవేళ (విలువ >= 0.5) intpart++;

	తిరిగి intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
స్థిర ద్విగుణ my_modf(ద్విగుణ x0, ద్విగుణ *iptr)
{
	పూర్ణాంకం i;
	దీర్ఘ l;
	ద్విగుణ x = x0;
	ద్విగుణ f = 1.0;

	కొరకు (i=0;i<100;i++) {
		l = (దీర్ఘ)x;
		ఒకవేళ (l <= (x+1) && l >= (x-1)) ఆపు;
		x *= 0.1;
		f *= 10.0;
	}

	ఒకవేళ (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		తిరిగి 0;
	}

	ఒకవేళ (i != 0) {
		ద్విగుణ i2;
		ద్విగుణ ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		తిరిగి ret;
	}

	(*iptr) = l;
	తిరిగి x - (*iptr);
}


స్థిర పూర్ణాంకం
fmtfp (అక్షరం *బఫరు, కొలత_t *currlen, కొలత_t maxlen,
    LDOUBLE fvalue, పూర్ణాంకం min, పూర్ణాంకం max, పూర్ణాంకం flags)
{
	పూర్ణాంకం signvalue = 0;
	ద్విగుణ ufvalue;
	అక్షరం iconvert[311];
	అక్షరం fconvert[311];
	పూర్ణాంకం iplace = 0;
	పూర్ణాంకం fplace = 0;
	పూర్ణాంకం padlen = 0; /* amount to pad */
	పూర్ణాంకం zpadlen = 0;
#ఒకవేళ 0
	పూర్ణాంకం caps = 0;
#అయితే_ముగింపు
	పూర్ణాంకం idx;
	ద్విగుణ intpart;
	ద్విగుణ fracpart;
	ద్విగుణ తాత్కాలిక;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	ఒకవేళ (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	ఒకవేళ (fvalue < 0) {
		signvalue = '-';
	} లేకపోతే {
		ఒకవేళ (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} లేకపోతే {
			ఒకవేళ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#ఒకవేళ 0
	ఒకవేళ (flags & DP_F_పైకి) caps = 1; /* Should characters be upper case? */
#అయితే_ముగింపు

#ఒకవేళ 0
	 ఒకవేళ (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#అయితే_ముగింపు

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	ఒకవేళ (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	తాత్కాలిక = ufvalue;
	my_modf(తాత్కాలిక, &intpart);

	fracpart = విడత_2((POW10(max)) * (ufvalue - intpart));

	ఒకవేళ (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	చేయి {
		తాత్కాలిక = intpart*0.1;
		my_modf(తాత్కాలిక, &intpart);
		idx = (పూర్ణాంకం) ((తాత్కాలిక -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} అయితే (intpart && (iplace < 311));
	ఒకవేళ (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	ఒకవేళ (fracpart)
	{
		చేయి {
			తాత్కాలిక = fracpart*0.1;
			my_modf(తాత్కాలిక, &fracpart);
			idx = (పూర్ణాంకం) ((తాత్కాలిక -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} అయితే(fracpart && (fplace < 311));
		ఒకవేళ (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	ఒకవేళ (zpadlen < 0) zpadlen = 0;
	ఒకవేళ (padlen < 0)
		padlen = 0;
	ఒకవేళ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	ఒకవేళ ((flags & DP_F_ZERO) && (padlen > 0)) {
		ఒకవేళ (signvalue) {
			DOPR_OUTCH(బఫరు, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		అయితే (padlen > 0) {
			DOPR_OUTCH(బఫరు, *currlen, maxlen, '0');
			--padlen;
		}
	}
	అయితే (padlen > 0) {
		DOPR_OUTCH(బఫరు, *currlen, maxlen, ' ');
		--padlen;
	}
	ఒకవేళ (signvalue)
		DOPR_OUTCH(బఫరు, *currlen, maxlen, signvalue);

	అయితే (iplace > 0) {
		--iplace;
		DOPR_OUTCH(బఫరు, *currlen, maxlen, iconvert[iplace]);
	}

#నిర్వచితమైతే DEBUG_SNPRINTF
	రాయి("fmtfp: fplace=%d zpadlen=%d\n", fplace, zpadlen);
#అయితే_ముగింపు

	/*
	 * Decimal point.  This should probably use locale to find the correct
	 * char to print out.
	 */
	ఒకవేళ (max > 0) {
		DOPR_OUTCH(బఫరు, *currlen, maxlen, '.');

		అయితే (zpadlen > 0) {
			DOPR_OUTCH(బఫరు, *currlen, maxlen, '0');
			--zpadlen;
		}

		అయితే (fplace > 0) {
			--fplace;
			DOPR_OUTCH(బఫరు, *currlen, maxlen, fconvert[fplace]);
		}
	}

	అయితే (padlen < 0) {
		DOPR_OUTCH(బఫరు, *currlen, maxlen, ' ');
		++padlen;
	}
	తిరిగి 0;
}
#అయితే_ముగింపు /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#ఒకవేళ !defined(HAVE_VSNPRINTF)
పూర్ణాంకం
vsnprintf (అక్షరం *str, కొలత_t లెక్క, స్థిరరాశి అక్షరం *fmt, va_list వాదనలు)
{
	తిరిగి dopr(str, లెక్క, fmt, వాదనలు);
}
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_SNPRINTF)
పూర్ణాంకం
snprintf(అక్షరం *str, కొలత_t లెక్క, SNPRINTF_CONST అక్షరం *fmt, ...)
{
	కొలత_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, లెక్క, fmt, ap);
	va_end(ap);
	తిరిగి ret;
}
#అయితే_ముగింపు
