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

#അന്തര്ഭാവ "includes.h"

#എങ്കിൽ defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#endif

#എങ്കിൽ !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <errno.h>

#ifdef HAVE_LONG_DOUBLE
# define LDOUBLE long ഇരട്ട
#അല്ലെങ്കിൽ
# define LDOUBLE ഇരട്ട
#endif

#ifdef HAVE_LONG_LONG
# define LLONG long long
#അല്ലെങ്കിൽ
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
#define DP_F_അക്കം	(1 << 3)
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
	ചെയ്യുക { \
		എങ്കിൽ (pos + 1 >= INT_MAX) { \
			errno = ERANGE; \
			തിരികെ -1; \
		} \
		എങ്കിൽ (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} ആകുമ്പോൾ (0)

സ്ഥിതം പൂർണ്ണസംഖ്യ dopr(അക്ഷരം *buffer, size_t maxlen, സ്ഥിരം അക്ഷരം *format,
    va_list args_in);
സ്ഥിതം പൂർണ്ണസംഖ്യ fmtstr(അക്ഷരം *buffer, size_t *currlen, size_t maxlen,
    അക്ഷരം *മൂല്യം, പൂർണ്ണസംഖ്യ flags, പൂർണ്ണസംഖ്യ min, പൂർണ്ണസംഖ്യ max);
സ്ഥിതം പൂർണ്ണസംഖ്യ fmtint(അക്ഷരം *buffer, size_t *currlen, size_t maxlen,
    intmax_t മൂല്യം, പൂർണ്ണസംഖ്യ base, പൂർണ്ണസംഖ്യ min, പൂർണ്ണസംഖ്യ max, പൂർണ്ണസംഖ്യ flags);
സ്ഥിതം പൂർണ്ണസംഖ്യ fmtfp(അക്ഷരം *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, പൂർണ്ണസംഖ്യ min, പൂർണ്ണസംഖ്യ max, പൂർണ്ണസംഖ്യ flags);

സ്ഥിതം പൂർണ്ണസംഖ്യ
dopr(അക്ഷരം *buffer, size_t maxlen, സ്ഥിരം അക്ഷരം *format, va_list args_in)
{
	അക്ഷരം ch;
	intmax_t മൂല്യം;
	LDOUBLE fvalue;
	അക്ഷരം *strvalue;
	പൂർണ്ണസംഖ്യ min;
	പൂർണ്ണസംഖ്യ max;
	പൂർണ്ണസംഖ്യ state;
	പൂർണ്ണസംഖ്യ flags;
	പൂർണ്ണസംഖ്യ cflags;
	size_t currlen;
	va_list args;

	VA_COPY(args, args_in);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	ആകുമ്പോൾ (state != DP_S_DONE) {
		എങ്കിൽ (ch == '\0')
			state = DP_S_DONE;

		തിരഞ്ഞെടുപ്പ്(state) {
		അവസ്ഥ DP_S_DEFAULT:
			എങ്കിൽ (ch == '%')
				state = DP_S_FLAGS;
			അല്ലെങ്കിൽ
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
			ch = *format++;
			നിർത്തുക;
		അവസ്ഥ DP_S_FLAGS:
			തിരഞ്ഞെടുപ്പ് (ch) {
			അവസ്ഥ '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				നിർത്തുക;
			അവസ്ഥ '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				നിർത്തുക;
			അവസ്ഥ ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				നിർത്തുക;
			അവസ്ഥ '#':
				flags |= DP_F_അക്കം;
				ch = *format++;
				നിർത്തുക;
			അവസ്ഥ '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				നിർത്തുക;
			സ്ഥിരസ്ഥിതി:
				state = DP_S_MIN;
				നിർത്തുക;
			}
			നിർത്തുക;
		അവസ്ഥ DP_S_MIN:
			എങ്കിൽ (isdigit((unsigned അക്ഷരം)ch)) {
				min = 10*min + char_to_int (ch);
				ch = *format++;
			} അല്ലെങ്കിൽ എങ്കിൽ (ch == '*') {
				min = va_arg (args, പൂർണ്ണസംഖ്യ);
				ch = *format++;
				state = DP_S_DOT;
			} അല്ലെങ്കിൽ {
				state = DP_S_DOT;
			}
			നിർത്തുക;
		അവസ്ഥ DP_S_DOT:
			എങ്കിൽ (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} അല്ലെങ്കിൽ {
				state = DP_S_MOD;
			}
			നിർത്തുക;
		അവസ്ഥ DP_S_MAX:
			എങ്കിൽ (isdigit((unsigned അക്ഷരം)ch)) {
				എങ്കിൽ (max < 0)
					max = 0;
				max = 10*max + char_to_int (ch);
				ch = *format++;
			} അല്ലെങ്കിൽ എങ്കിൽ (ch == '*') {
				max = va_arg (args, പൂർണ്ണസംഖ്യ);
				ch = *format++;
				state = DP_S_MOD;
			} അല്ലെങ്കിൽ {
				state = DP_S_MOD;
			}
			നിർത്തുക;
		അവസ്ഥ DP_S_MOD:
			തിരഞ്ഞെടുപ്പ് (ch) {
			അവസ്ഥ 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				നിർത്തുക;
			അവസ്ഥ 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				നിർത്തുക;
			അവസ്ഥ 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				എങ്കിൽ (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				നിർത്തുക;
			അവസ്ഥ 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				നിർത്തുക;
			അവസ്ഥ 'z':
				cflags = DP_C_SIZE;
				ch = *format++;
				നിർത്തുക;
			സ്ഥിരസ്ഥിതി:
				നിർത്തുക;
			}
			state = DP_S_CONV;
			നിർത്തുക;
		അവസ്ഥ DP_S_CONV:
			തിരഞ്ഞെടുപ്പ് (ch) {
			അവസ്ഥ 'd':
			അവസ്ഥ 'i':
				എങ്കിൽ (cflags == DP_C_SHORT)
					മൂല്യം = va_arg (args, പൂർണ്ണസംഖ്യ);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_LONG)
					മൂല്യം = va_arg (args, long പൂർണ്ണസംഖ്യ);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_LLONG)
					മൂല്യം = va_arg (args, LLONG);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_SIZE)
					മൂല്യം = va_arg (args, ssize_t);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_INTMAX)
					മൂല്യം = va_arg (args, intmax_t);
				അല്ലെങ്കിൽ
					മൂല്യം = va_arg (args, പൂർണ്ണസംഖ്യ);
				എങ്കിൽ (fmtint(buffer, &currlen, maxlen,
				    മൂല്യം, 10, min, max, flags) == -1)
					പോകുക fail;
				നിർത്തുക;
			അവസ്ഥ 'o':
				flags |= DP_F_UNSIGNED;
				എങ്കിൽ (cflags == DP_C_SHORT)
					മൂല്യം = va_arg (args, unsigned പൂർണ്ണസംഖ്യ);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_LONG)
					മൂല്യം = (long)va_arg (args, unsigned long പൂർണ്ണസംഖ്യ);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_LLONG)
					മൂല്യം = (long)va_arg (args, unsigned LLONG);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_SIZE)
					മൂല്യം = va_arg (args, size_t);
#ifdef notyet
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_INTMAX)
					മൂല്യം = va_arg (args, uintmax_t);
#endif
				അല്ലെങ്കിൽ
					മൂല്യം = (long)va_arg (args, unsigned പൂർണ്ണസംഖ്യ);
				എങ്കിൽ (fmtint(buffer, &currlen, maxlen, മൂല്യം,
				    8, min, max, flags) == -1)
					പോകുക fail;
				നിർത്തുക;
			അവസ്ഥ 'u':
				flags |= DP_F_UNSIGNED;
				എങ്കിൽ (cflags == DP_C_SHORT)
					മൂല്യം = va_arg (args, unsigned പൂർണ്ണസംഖ്യ);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_LONG)
					മൂല്യം = (long)va_arg (args, unsigned long പൂർണ്ണസംഖ്യ);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_LLONG)
					മൂല്യം = (LLONG)va_arg (args, unsigned LLONG);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_SIZE)
					മൂല്യം = va_arg (args, size_t);
#ifdef notyet
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_INTMAX)
					മൂല്യം = va_arg (args, uintmax_t);
#endif
				അല്ലെങ്കിൽ
					മൂല്യം = (long)va_arg (args, unsigned പൂർണ്ണസംഖ്യ);
				എങ്കിൽ (fmtint(buffer, &currlen, maxlen, മൂല്യം,
				    10, min, max, flags) == -1)
					പോകുക fail;
				നിർത്തുക;
			അവസ്ഥ 'X':
				flags |= DP_F_UP;
			അവസ്ഥ 'x':
				flags |= DP_F_UNSIGNED;
				എങ്കിൽ (cflags == DP_C_SHORT)
					മൂല്യം = va_arg (args, unsigned പൂർണ്ണസംഖ്യ);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_LONG)
					മൂല്യം = (long)va_arg (args, unsigned long പൂർണ്ണസംഖ്യ);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_LLONG)
					മൂല്യം = (LLONG)va_arg (args, unsigned LLONG);
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_SIZE)
					മൂല്യം = va_arg (args, size_t);
#ifdef notyet
				അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_INTMAX)
					മൂല്യം = va_arg (args, uintmax_t);
#endif
				അല്ലെങ്കിൽ
					മൂല്യം = (long)va_arg (args, unsigned പൂർണ്ണസംഖ്യ);
				എങ്കിൽ (fmtint(buffer, &currlen, maxlen, മൂല്യം,
				    16, min, max, flags) == -1)
					പോകുക fail;
				നിർത്തുക;
			അവസ്ഥ 'f':
				എങ്കിൽ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				അല്ലെങ്കിൽ
					fvalue = va_arg (args, ഇരട്ട);
				എങ്കിൽ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					പോകുക fail;
				നിർത്തുക;
			അവസ്ഥ 'E':
				flags |= DP_F_UP;
			അവസ്ഥ 'e':
				എങ്കിൽ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				അല്ലെങ്കിൽ
					fvalue = va_arg (args, ഇരട്ട);
				എങ്കിൽ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					പോകുക fail;
				നിർത്തുക;
			അവസ്ഥ 'G':
				flags |= DP_F_UP;
			അവസ്ഥ 'g':
				എങ്കിൽ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (args, LDOUBLE);
				അല്ലെങ്കിൽ
					fvalue = va_arg (args, ഇരട്ട);
				എങ്കിൽ (fmtfp(buffer, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					പോകുക fail;
				നിർത്തുക;
			അവസ്ഥ 'c':
				DOPR_OUTCH(buffer, currlen, maxlen,
				    va_arg (args, പൂർണ്ണസംഖ്യ));
				നിർത്തുക;
			അവസ്ഥ 's':
				strvalue = va_arg (args, അക്ഷരം *);
				എങ്കിൽ (!strvalue) strvalue = "(NULL)";
				എങ്കിൽ (max == -1) {
					max = strlen(strvalue);
				}
				എങ്കിൽ (min > 0 && max >= 0 && min > max) max = min;
				എങ്കിൽ (fmtstr(buffer, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					പോകുക fail;
				നിർത്തുക;
			അവസ്ഥ 'p':
				strvalue = va_arg (args, ശൂന്യം *);
				എങ്കിൽ (fmtint(buffer, &currlen, maxlen,
				    (long) strvalue, 16, min, max, flags) == -1)
					പോകുക fail;
				നിർത്തുക;
#എങ്കിൽ we_dont_want_this_in_openssh
			അവസ്ഥ 'n':
				എങ്കിൽ (cflags == DP_C_SHORT) {
					short പൂർണ്ണസംഖ്യ *അക്കം;
					അക്കം = va_arg (args, short പൂർണ്ണസംഖ്യ *);
					*അക്കം = currlen;
				} അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_LONG) {
					long പൂർണ്ണസംഖ്യ *അക്കം;
					അക്കം = va_arg (args, long പൂർണ്ണസംഖ്യ *);
					*അക്കം = (long പൂർണ്ണസംഖ്യ)currlen;
				} അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_LLONG) {
					LLONG *അക്കം;
					അക്കം = va_arg (args, LLONG *);
					*അക്കം = (LLONG)currlen;
				} അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_SIZE) {
					ssize_t *അക്കം;
					അക്കം = va_arg (args, ssize_t *);
					*അക്കം = (ssize_t)currlen;
				} അല്ലെങ്കിൽ എങ്കിൽ (cflags == DP_C_INTMAX) {
					intmax_t *അക്കം;
					അക്കം = va_arg (args, intmax_t *);
					*അക്കം = (intmax_t)currlen;
				} അല്ലെങ്കിൽ {
					പൂർണ്ണസംഖ്യ *അക്കം;
					അക്കം = va_arg (args, പൂർണ്ണസംഖ്യ *);
					*അക്കം = currlen;
				}
				നിർത്തുക;
#endif
			അവസ്ഥ '%':
				DOPR_OUTCH(buffer, currlen, maxlen, ch);
				നിർത്തുക;
			സ്ഥിരസ്ഥിതി:
				/* Unknown, skip */
				നിർത്തുക;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			നിർത്തുക;
		അവസ്ഥ DP_S_DONE:
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			/* hmm? */
			നിർത്തുക; /* some picky compilers need this */
		}
	}
	എങ്കിൽ (maxlen != 0) {
		എങ്കിൽ (currlen < maxlen - 1)
			buffer[currlen] = '\0';
		അല്ലെങ്കിൽ എങ്കിൽ (maxlen > 0)
			buffer[maxlen - 1] = '\0';
	}
	va_end(args);
	തിരികെ currlen < INT_MAX ? (പൂർണ്ണസംഖ്യ)currlen : -1;
 fail:
	va_end(args);
	തിരികെ -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
fmtstr(അക്ഷരം *buffer, size_t *currlen, size_t maxlen,
    അക്ഷരം *മൂല്യം, പൂർണ്ണസംഖ്യ flags, പൂർണ്ണസംഖ്യ min, പൂർണ്ണസംഖ്യ max)
{
	പൂർണ്ണസംഖ്യ padlen, strln;     /* amount to pad */
	പൂർണ്ണസംഖ്യ cnt = 0;

#ifdef DEBUG_SNPRINTF
	printf("fmtstr min=%d max=%d s=[%s]\n", min, max, മൂല്യം);
#endif
	എങ്കിൽ (മൂല്യം == 0) {
		മൂല്യം = "<NULL>";
	}

	വേണ്ടി (strln = 0; strln < max && മൂല്യം[strln]; ++strln); /* strlen */
	padlen = min - strln;
	എങ്കിൽ (padlen < 0)
		padlen = 0;
	എങ്കിൽ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	ആകുമ്പോൾ ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	ആകുമ്പോൾ (*മൂല്യം && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, *മൂല്യം);
		മൂല്യം++;
		++cnt;
	}
	ആകുമ്പോൾ ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	തിരികെ 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

സ്ഥിതം പൂർണ്ണസംഖ്യ
fmtint(അക്ഷരം *buffer, size_t *currlen, size_t maxlen,
    intmax_t മൂല്യം, പൂർണ്ണസംഖ്യ base, പൂർണ്ണസംഖ്യ min, പൂർണ്ണസംഖ്യ max, പൂർണ്ണസംഖ്യ flags)
{
	പൂർണ്ണസംഖ്യ signvalue = 0;
	unsigned LLONG uvalue;
	അക്ഷരം convert[20];
	പൂർണ്ണസംഖ്യ place = 0;
	പൂർണ്ണസംഖ്യ spadlen = 0; /* amount to space pad */
	പൂർണ്ണസംഖ്യ zpadlen = 0; /* amount to zero pad */
	പൂർണ്ണസംഖ്യ caps = 0;

	എങ്കിൽ (max < 0)
		max = 0;

	uvalue = മൂല്യം;

	എങ്കിൽ(!(flags & DP_F_UNSIGNED)) {
		എങ്കിൽ( മൂല്യം < 0 ) {
			signvalue = '-';
			uvalue = -മൂല്യം;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			അല്ലെങ്കിൽ എങ്കിൽ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	എങ്കിൽ (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */

	ചെയ്യുക {
		convert[place++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (unsigned)base  ];
		uvalue = (uvalue / (unsigned)base );
	} ആകുമ്പോൾ(uvalue && (place < 20));
	എങ്കിൽ (place == 20) place--;
	convert[place] = 0;

	zpadlen = max - place;
	spadlen = min - MAX (max, place) - (signvalue ? 1 : 0);
	എങ്കിൽ (zpadlen < 0) zpadlen = 0;
	എങ്കിൽ (spadlen < 0) spadlen = 0;
	എങ്കിൽ (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	എങ്കിൽ (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ifdef DEBUG_SNPRINTF
	printf("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, place);
#endif

	/* Spaces */
	ആകുമ്പോൾ (spadlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	എങ്കിൽ (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	/* Zeros */
	എങ്കിൽ (zpadlen > 0) {
		ആകുമ്പോൾ (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	ആകുമ്പോൾ (place > 0) {
		--place;
		DOPR_OUTCH(buffer, *currlen, maxlen, convert[place]);
	}

	/* Left Justified spaces */
	ആകുമ്പോൾ (spadlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++spadlen;
	}
	തിരികെ 0;
}

സ്ഥിതം LDOUBLE abs_val(LDOUBLE മൂല്യം)
{
	LDOUBLE result = മൂല്യം;

	എങ്കിൽ (മൂല്യം < 0)
		result = -മൂല്യം;

	തിരികെ result;
}

സ്ഥിതം LDOUBLE POW10(പൂർണ്ണസംഖ്യ val)
{
	LDOUBLE result = 1;

	ആകുമ്പോൾ (val) {
		result *= 10;
		val--;
	}

	തിരികെ result;
}

സ്ഥിതം LLONG ROUND(LDOUBLE മൂല്യം)
{
	LLONG intpart;

	intpart = (LLONG)മൂല്യം;
	മൂല്യം = മൂല്യം - intpart;
	എങ്കിൽ (മൂല്യം >= 0.5) intpart++;

	തിരികെ intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
സ്ഥിതം ഇരട്ട my_modf(ഇരട്ട x0, ഇരട്ട *iptr)
{
	പൂർണ്ണസംഖ്യ i;
	long l;
	ഇരട്ട x = x0;
	ഇരട്ട f = 1.0;

	വേണ്ടി (i=0;i<100;i++) {
		l = (long)x;
		എങ്കിൽ (l <= (x+1) && l >= (x-1)) നിർത്തുക;
		x *= 0.1;
		f *= 10.0;
	}

	എങ്കിൽ (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		തിരികെ 0;
	}

	എങ്കിൽ (i != 0) {
		ഇരട്ട i2;
		ഇരട്ട ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		തിരികെ ret;
	}

	(*iptr) = l;
	തിരികെ x - (*iptr);
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
fmtfp (അക്ഷരം *buffer, size_t *currlen, size_t maxlen,
    LDOUBLE fvalue, പൂർണ്ണസംഖ്യ min, പൂർണ്ണസംഖ്യ max, പൂർണ്ണസംഖ്യ flags)
{
	പൂർണ്ണസംഖ്യ signvalue = 0;
	ഇരട്ട ufvalue;
	അക്ഷരം iconvert[311];
	അക്ഷരം fconvert[311];
	പൂർണ്ണസംഖ്യ iplace = 0;
	പൂർണ്ണസംഖ്യ fplace = 0;
	പൂർണ്ണസംഖ്യ padlen = 0; /* amount to pad */
	പൂർണ്ണസംഖ്യ zpadlen = 0;
#എങ്കിൽ 0
	പൂർണ്ണസംഖ്യ caps = 0;
#endif
	പൂർണ്ണസംഖ്യ idx;
	ഇരട്ട intpart;
	ഇരട്ട fracpart;
	ഇരട്ട temp;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	എങ്കിൽ (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	എങ്കിൽ (fvalue < 0) {
		signvalue = '-';
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#എങ്കിൽ 0
	എങ്കിൽ (flags & DP_F_UP) caps = 1; /* Should characters be upper case? */
#endif

#എങ്കിൽ 0
	 എങ്കിൽ (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#endif

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	എങ്കിൽ (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	temp = ufvalue;
	my_modf(temp, &intpart);

	fracpart = ROUND((POW10(max)) * (ufvalue - intpart));

	എങ്കിൽ (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	ചെയ്യുക {
		temp = intpart*0.1;
		my_modf(temp, &intpart);
		idx = (പൂർണ്ണസംഖ്യ) ((temp -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} ആകുമ്പോൾ (intpart && (iplace < 311));
	എങ്കിൽ (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	എങ്കിൽ (fracpart)
	{
		ചെയ്യുക {
			temp = fracpart*0.1;
			my_modf(temp, &fracpart);
			idx = (പൂർണ്ണസംഖ്യ) ((temp -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} ആകുമ്പോൾ(fracpart && (fplace < 311));
		എങ്കിൽ (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	എങ്കിൽ (zpadlen < 0) zpadlen = 0;
	എങ്കിൽ (padlen < 0)
		padlen = 0;
	എങ്കിൽ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	എങ്കിൽ ((flags & DP_F_ZERO) && (padlen > 0)) {
		എങ്കിൽ (signvalue) {
			DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		ആകുമ്പോൾ (padlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--padlen;
		}
	}
	ആകുമ്പോൾ (padlen > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		--padlen;
	}
	എങ്കിൽ (signvalue)
		DOPR_OUTCH(buffer, *currlen, maxlen, signvalue);

	ആകുമ്പോൾ (iplace > 0) {
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
	എങ്കിൽ (max > 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, '.');

		ആകുമ്പോൾ (zpadlen > 0) {
			DOPR_OUTCH(buffer, *currlen, maxlen, '0');
			--zpadlen;
		}

		ആകുമ്പോൾ (fplace > 0) {
			--fplace;
			DOPR_OUTCH(buffer, *currlen, maxlen, fconvert[fplace]);
		}
	}

	ആകുമ്പോൾ (padlen < 0) {
		DOPR_OUTCH(buffer, *currlen, maxlen, ' ');
		++padlen;
	}
	തിരികെ 0;
}
#endif /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#എങ്കിൽ !defined(HAVE_VSNPRINTF)
പൂർണ്ണസംഖ്യ
vsnprintf (അക്ഷരം *str, size_t എണ്ണം, സ്ഥിരം അക്ഷരം *fmt, va_list args)
{
	തിരികെ dopr(str, എണ്ണം, fmt, args);
}
#endif

#എങ്കിൽ !defined(HAVE_SNPRINTF)
പൂർണ്ണസംഖ്യ
snprintf(അക്ഷരം *str, size_t എണ്ണം, SNPRINTF_CONST അക്ഷരം *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, എണ്ണം, fmt, ap);
	va_end(ap);
	തിരികെ ret;
}
#endif
