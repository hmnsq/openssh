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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ defined(BROKEN_SNPRINTF)		/* For those with broken snprintf() */
# undef HAVE_SNPRINTF
# undef HAVE_VSNPRINTF
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF)

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LONG_DOUBLE
# define LDOUBLE ਲੰਮਾ ਦੁੱਗਣਾ
#ਨਹੀਂਤਾਂ
# define LDOUBLE ਦੁੱਗਣਾ
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LONG_LONG
# define LLONG ਲੰਮਾ ਲੰਮਾ
#ਨਹੀਂਤਾਂ
# define LLONG ਲੰਮਾ
#ਜੇ_ਅੰਤ

/*
 * dopr(): poor man's version of doprintf
 */

/* format read states */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_S_DEFAULT 0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_S_FLAGS   1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_S_MIN     2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_S_DOT     3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_S_MAX     4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_S_MOD     5
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_S_CONV    6
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_S_ਪੂਰਾ    7

/* format flags - Bits */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_F_MINUS	(1 << 0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_F_PLUS	(1 << 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_F_SPACE	(1 << 2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_F_ਅੰਕ	(1 << 3)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_F_ZERO	(1 << 4)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_F_ਉੱਪਰ		(1 << 5)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_F_UNSIGNED	(1 << 6)

/* Conversion Flags */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_C_SHORT   1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_C_LONG    2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_C_LDOUBLE 3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_C_LLONG   4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_C_ਮਾਪ    5
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DP_C_INTMAX  6

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ char_ਮੰਜ਼ਿਲ_int(p) ((p)- '0')
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ MAX
# define MAX(p,q) (((p) >= (q)) ? (p) : (q))
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DOPR_OUTCH(buf, pos, buflen, thechar) \
	ਕਰੋ { \
		ਜੇ (pos + 1 >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) { \
			errno = ERANGE; \
			ਵਾਪਸ -1; \
		} \
		ਜੇ (pos < buflen) \
			buf[pos] = thechar; \
		(pos)++; \
	} ਜਦੋਂ (0)

ਸਥਿਰ ਪੂਰਨ dopr(ਅੱਖਰ *ਬਫਰ, ਮਾਪ_t maxlen, ਅਚਲ ਅੱਖਰ *format,
    va_list ਦਲੀਲਾਂ_ਵਿੱਚ);
ਸਥਿਰ ਪੂਰਨ fmtstr(ਅੱਖਰ *ਬਫਰ, ਮਾਪ_t *currlen, ਮਾਪ_t maxlen,
    ਅੱਖਰ *ਮੁੱਲ, ਪੂਰਨ flags, ਪੂਰਨ min, ਪੂਰਨ max);
ਸਥਿਰ ਪੂਰਨ fmtint(ਅੱਖਰ *ਬਫਰ, ਮਾਪ_t *currlen, ਮਾਪ_t maxlen,
    intmax_t ਮੁੱਲ, ਪੂਰਨ ਅਧਾਰ, ਪੂਰਨ min, ਪੂਰਨ max, ਪੂਰਨ flags);
ਸਥਿਰ ਪੂਰਨ fmtfp(ਅੱਖਰ *ਬਫਰ, ਮਾਪ_t *currlen, ਮਾਪ_t maxlen,
    LDOUBLE fvalue, ਪੂਰਨ min, ਪੂਰਨ max, ਪੂਰਨ flags);

ਸਥਿਰ ਪੂਰਨ
dopr(ਅੱਖਰ *ਬਫਰ, ਮਾਪ_t maxlen, ਅਚਲ ਅੱਖਰ *format, va_list ਦਲੀਲਾਂ_ਵਿੱਚ)
{
	ਅੱਖਰ ch;
	intmax_t ਮੁੱਲ;
	LDOUBLE fvalue;
	ਅੱਖਰ *strvalue;
	ਪੂਰਨ min;
	ਪੂਰਨ max;
	ਪੂਰਨ state;
	ਪੂਰਨ flags;
	ਪੂਰਨ cflags;
	ਮਾਪ_t currlen;
	va_list ਦਲੀਲਾਂ;

	VA_COPY(ਦਲੀਲਾਂ, ਦਲੀਲਾਂ_ਵਿੱਚ);

	state = DP_S_DEFAULT;
	currlen = flags = cflags = min = 0;
	max = -1;
	ch = *format++;

	ਜਦੋਂ (state != DP_S_ਪੂਰਾ) {
		ਜੇ (ch == '\0')
			state = DP_S_ਪੂਰਾ;

		ਚੋਣ(state) {
		ਹਾਲਤ DP_S_DEFAULT:
			ਜੇ (ch == '%')
				state = DP_S_FLAGS;
			ਨਹੀਂਤਾਂ
				DOPR_OUTCH(ਬਫਰ, currlen, maxlen, ch);
			ch = *format++;
			ਰੋਕੋ;
		ਹਾਲਤ DP_S_FLAGS:
			ਚੋਣ (ch) {
			ਹਾਲਤ '-':
				flags |= DP_F_MINUS;
				ch = *format++;
				ਰੋਕੋ;
			ਹਾਲਤ '+':
				flags |= DP_F_PLUS;
				ch = *format++;
				ਰੋਕੋ;
			ਹਾਲਤ ' ':
				flags |= DP_F_SPACE;
				ch = *format++;
				ਰੋਕੋ;
			ਹਾਲਤ '#':
				flags |= DP_F_ਅੰਕ;
				ch = *format++;
				ਰੋਕੋ;
			ਹਾਲਤ '0':
				flags |= DP_F_ZERO;
				ch = *format++;
				ਰੋਕੋ;
			ਮੂਲ:
				state = DP_S_MIN;
				ਰੋਕੋ;
			}
			ਰੋਕੋ;
		ਹਾਲਤ DP_S_MIN:
			ਜੇ (ਅੰਕ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)ch)) {
				min = 10*min + char_ਮੰਜ਼ਿਲ_int (ch);
				ch = *format++;
			} ਨਹੀਂਤਾਂ ਜੇ (ch == '*') {
				min = va_arg (ਦਲੀਲਾਂ, ਪੂਰਨ);
				ch = *format++;
				state = DP_S_DOT;
			} ਨਹੀਂਤਾਂ {
				state = DP_S_DOT;
			}
			ਰੋਕੋ;
		ਹਾਲਤ DP_S_DOT:
			ਜੇ (ch == '.') {
				state = DP_S_MAX;
				ch = *format++;
			} ਨਹੀਂਤਾਂ {
				state = DP_S_MOD;
			}
			ਰੋਕੋ;
		ਹਾਲਤ DP_S_MAX:
			ਜੇ (ਅੰਕ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)ch)) {
				ਜੇ (max < 0)
					max = 0;
				max = 10*max + char_ਮੰਜ਼ਿਲ_int (ch);
				ch = *format++;
			} ਨਹੀਂਤਾਂ ਜੇ (ch == '*') {
				max = va_arg (ਦਲੀਲਾਂ, ਪੂਰਨ);
				ch = *format++;
				state = DP_S_MOD;
			} ਨਹੀਂਤਾਂ {
				state = DP_S_MOD;
			}
			ਰੋਕੋ;
		ਹਾਲਤ DP_S_MOD:
			ਚੋਣ (ch) {
			ਹਾਲਤ 'h':
				cflags = DP_C_SHORT;
				ch = *format++;
				ਰੋਕੋ;
			ਹਾਲਤ 'j':
				cflags = DP_C_INTMAX;
				ch = *format++;
				ਰੋਕੋ;
			ਹਾਲਤ 'l':
				cflags = DP_C_LONG;
				ch = *format++;
				ਜੇ (ch == 'l') {	/* It's a long long */
					cflags = DP_C_LLONG;
					ch = *format++;
				}
				ਰੋਕੋ;
			ਹਾਲਤ 'L':
				cflags = DP_C_LDOUBLE;
				ch = *format++;
				ਰੋਕੋ;
			ਹਾਲਤ 'z':
				cflags = DP_C_ਮਾਪ;
				ch = *format++;
				ਰੋਕੋ;
			ਮੂਲ:
				ਰੋਕੋ;
			}
			state = DP_S_CONV;
			ਰੋਕੋ;
		ਹਾਲਤ DP_S_CONV:
			ਚੋਣ (ch) {
			ਹਾਲਤ 'd':
			ਹਾਲਤ 'i':
				ਜੇ (cflags == DP_C_SHORT)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, ਪੂਰਨ);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_LONG)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, ਲੰਮਾ ਪੂਰਨ);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_LLONG)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, LLONG);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_ਮਾਪ)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, ssize_t);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_INTMAX)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, intmax_t);
				ਨਹੀਂਤਾਂ
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, ਪੂਰਨ);
				ਜੇ (fmtint(ਬਫਰ, &currlen, maxlen,
				    ਮੁੱਲ, 10, min, max, flags) == -1)
					ਜਾਓ fail;
				ਰੋਕੋ;
			ਹਾਲਤ 'o':
				flags |= DP_F_UNSIGNED;
				ਜੇ (cflags == DP_C_SHORT)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_LONG)
					ਮੁੱਲ = (ਲੰਮਾ)va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਪੂਰਨ);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_LLONG)
					ਮੁੱਲ = (ਲੰਮਾ)va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ LLONG);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_ਮਾਪ)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, ਮਾਪ_t);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ notyet
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_INTMAX)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, uintmax_t);
#ਜੇ_ਅੰਤ
				ਨਹੀਂਤਾਂ
					ਮੁੱਲ = (ਲੰਮਾ)va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ);
				ਜੇ (fmtint(ਬਫਰ, &currlen, maxlen, ਮੁੱਲ,
				    8, min, max, flags) == -1)
					ਜਾਓ fail;
				ਰੋਕੋ;
			ਹਾਲਤ 'u':
				flags |= DP_F_UNSIGNED;
				ਜੇ (cflags == DP_C_SHORT)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_LONG)
					ਮੁੱਲ = (ਲੰਮਾ)va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਪੂਰਨ);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_LLONG)
					ਮੁੱਲ = (LLONG)va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ LLONG);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_ਮਾਪ)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, ਮਾਪ_t);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ notyet
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_INTMAX)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, uintmax_t);
#ਜੇ_ਅੰਤ
				ਨਹੀਂਤਾਂ
					ਮੁੱਲ = (ਲੰਮਾ)va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ);
				ਜੇ (fmtint(ਬਫਰ, &currlen, maxlen, ਮੁੱਲ,
				    10, min, max, flags) == -1)
					ਜਾਓ fail;
				ਰੋਕੋ;
			ਹਾਲਤ 'X':
				flags |= DP_F_ਉੱਪਰ;
			ਹਾਲਤ 'x':
				flags |= DP_F_UNSIGNED;
				ਜੇ (cflags == DP_C_SHORT)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_LONG)
					ਮੁੱਲ = (ਲੰਮਾ)va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਪੂਰਨ);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_LLONG)
					ਮੁੱਲ = (LLONG)va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ LLONG);
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_ਮਾਪ)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, ਮਾਪ_t);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ notyet
				ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_INTMAX)
					ਮੁੱਲ = va_arg (ਦਲੀਲਾਂ, uintmax_t);
#ਜੇ_ਅੰਤ
				ਨਹੀਂਤਾਂ
					ਮੁੱਲ = (ਲੰਮਾ)va_arg (ਦਲੀਲਾਂ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ);
				ਜੇ (fmtint(ਬਫਰ, &currlen, maxlen, ਮੁੱਲ,
				    16, min, max, flags) == -1)
					ਜਾਓ fail;
				ਰੋਕੋ;
			ਹਾਲਤ 'f':
				ਜੇ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (ਦਲੀਲਾਂ, LDOUBLE);
				ਨਹੀਂਤਾਂ
					fvalue = va_arg (ਦਲੀਲਾਂ, ਦੁੱਗਣਾ);
				ਜੇ (fmtfp(ਬਫਰ, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ਜਾਓ fail;
				ਰੋਕੋ;
			ਹਾਲਤ 'E':
				flags |= DP_F_ਉੱਪਰ;
			ਹਾਲਤ 'e':
				ਜੇ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (ਦਲੀਲਾਂ, LDOUBLE);
				ਨਹੀਂਤਾਂ
					fvalue = va_arg (ਦਲੀਲਾਂ, ਦੁੱਗਣਾ);
				ਜੇ (fmtfp(ਬਫਰ, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ਜਾਓ fail;
				ਰੋਕੋ;
			ਹਾਲਤ 'G':
				flags |= DP_F_ਉੱਪਰ;
			ਹਾਲਤ 'g':
				ਜੇ (cflags == DP_C_LDOUBLE)
					fvalue = va_arg (ਦਲੀਲਾਂ, LDOUBLE);
				ਨਹੀਂਤਾਂ
					fvalue = va_arg (ਦਲੀਲਾਂ, ਦੁੱਗਣਾ);
				ਜੇ (fmtfp(ਬਫਰ, &currlen, maxlen, fvalue,
				    min, max, flags) == -1)
					ਜਾਓ fail;
				ਰੋਕੋ;
			ਹਾਲਤ 'c':
				DOPR_OUTCH(ਬਫਰ, currlen, maxlen,
				    va_arg (ਦਲੀਲਾਂ, ਪੂਰਨ));
				ਰੋਕੋ;
			ਹਾਲਤ 's':
				strvalue = va_arg (ਦਲੀਲਾਂ, ਅੱਖਰ *);
				ਜੇ (!strvalue) strvalue = "(NULL)";
				ਜੇ (max == -1) {
					max = ਲੜੀ_ਲੰਬਾਈ(strvalue);
				}
				ਜੇ (min > 0 && max >= 0 && min > max) max = min;
				ਜੇ (fmtstr(ਬਫਰ, &currlen, maxlen,
				    strvalue, flags, min, max) == -1)
					ਜਾਓ fail;
				ਰੋਕੋ;
			ਹਾਲਤ 'p':
				strvalue = va_arg (ਦਲੀਲਾਂ, ਖਾਲੀ *);
				ਜੇ (fmtint(ਬਫਰ, &currlen, maxlen,
				    (ਲੰਮਾ) strvalue, 16, min, max, flags) == -1)
					ਜਾਓ fail;
				ਰੋਕੋ;
#ਜੇ we_dont_want_this_ਵਿੱਚ_openssh
			ਹਾਲਤ 'n':
				ਜੇ (cflags == DP_C_SHORT) {
					ਛੋਟਾ ਪੂਰਨ *ਅੰਕ;
					ਅੰਕ = va_arg (ਦਲੀਲਾਂ, ਛੋਟਾ ਪੂਰਨ *);
					*ਅੰਕ = currlen;
				} ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_LONG) {
					ਲੰਮਾ ਪੂਰਨ *ਅੰਕ;
					ਅੰਕ = va_arg (ਦਲੀਲਾਂ, ਲੰਮਾ ਪੂਰਨ *);
					*ਅੰਕ = (ਲੰਮਾ ਪੂਰਨ)currlen;
				} ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_LLONG) {
					LLONG *ਅੰਕ;
					ਅੰਕ = va_arg (ਦਲੀਲਾਂ, LLONG *);
					*ਅੰਕ = (LLONG)currlen;
				} ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_ਮਾਪ) {
					ssize_t *ਅੰਕ;
					ਅੰਕ = va_arg (ਦਲੀਲਾਂ, ssize_t *);
					*ਅੰਕ = (ssize_t)currlen;
				} ਨਹੀਂਤਾਂ ਜੇ (cflags == DP_C_INTMAX) {
					intmax_t *ਅੰਕ;
					ਅੰਕ = va_arg (ਦਲੀਲਾਂ, intmax_t *);
					*ਅੰਕ = (intmax_t)currlen;
				} ਨਹੀਂਤਾਂ {
					ਪੂਰਨ *ਅੰਕ;
					ਅੰਕ = va_arg (ਦਲੀਲਾਂ, ਪੂਰਨ *);
					*ਅੰਕ = currlen;
				}
				ਰੋਕੋ;
#ਜੇ_ਅੰਤ
			ਹਾਲਤ '%':
				DOPR_OUTCH(ਬਫਰ, currlen, maxlen, ch);
				ਰੋਕੋ;
			ਮੂਲ:
				/* Unknown, skip */
				ਰੋਕੋ;
			}
			ch = *format++;
			state = DP_S_DEFAULT;
			flags = cflags = min = 0;
			max = -1;
			ਰੋਕੋ;
		ਹਾਲਤ DP_S_ਪੂਰਾ:
			ਰੋਕੋ;
		ਮੂਲ:
			/* hmm? */
			ਰੋਕੋ; /* some picky compilers need this */
		}
	}
	ਜੇ (maxlen != 0) {
		ਜੇ (currlen < maxlen - 1)
			ਬਫਰ[currlen] = '\0';
		ਨਹੀਂਤਾਂ ਜੇ (maxlen > 0)
			ਬਫਰ[maxlen - 1] = '\0';
	}
	va_end(ਦਲੀਲਾਂ);
	ਵਾਪਸ currlen < ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ ? (ਪੂਰਨ)currlen : -1;
 fail:
	va_end(ਦਲੀਲਾਂ);
	ਵਾਪਸ -1;
}

ਸਥਿਰ ਪੂਰਨ
fmtstr(ਅੱਖਰ *ਬਫਰ, ਮਾਪ_t *currlen, ਮਾਪ_t maxlen,
    ਅੱਖਰ *ਮੁੱਲ, ਪੂਰਨ flags, ਪੂਰਨ min, ਪੂਰਨ max)
{
	ਪੂਰਨ padlen, strln;     /* amount to pad */
	ਪੂਰਨ cnt = 0;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SNPRINTF
	ਲਿਖੋ("fmtstr min=%d max=%d s=[%s]\n", min, max, ਮੁੱਲ);
#ਜੇ_ਅੰਤ
	ਜੇ (ਮੁੱਲ == 0) {
		ਮੁੱਲ = "<NULL>";
	}

	ਲਈ (strln = 0; strln < max && ਮੁੱਲ[strln]; ++strln); /* strlen */
	padlen = min - strln;
	ਜੇ (padlen < 0)
		padlen = 0;
	ਜੇ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justify */

	ਜਦੋਂ ((padlen > 0) && (cnt < max)) {
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, ' ');
		--padlen;
		++cnt;
	}
	ਜਦੋਂ (*ਮੁੱਲ && (cnt < max)) {
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, *ਮੁੱਲ);
		ਮੁੱਲ++;
		++cnt;
	}
	ਜਦੋਂ ((padlen < 0) && (cnt < max)) {
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, ' ');
		++padlen;
		++cnt;
	}
	ਵਾਪਸ 0;
}

/* Have to handle DP_F_NUM (ie 0x and 0 alternates) */

ਸਥਿਰ ਪੂਰਨ
fmtint(ਅੱਖਰ *ਬਫਰ, ਮਾਪ_t *currlen, ਮਾਪ_t maxlen,
    intmax_t ਮੁੱਲ, ਪੂਰਨ ਅਧਾਰ, ਪੂਰਨ min, ਪੂਰਨ max, ਪੂਰਨ flags)
{
	ਪੂਰਨ signvalue = 0;
	ਬਿਨਾਨਿਸ਼ਾਨੀ LLONG uvalue;
	ਅੱਖਰ convert[20];
	ਪੂਰਨ ਰੱਖੋ = 0;
	ਪੂਰਨ spadlen = 0; /* amount to space pad */
	ਪੂਰਨ zpadlen = 0; /* amount to zero pad */
	ਪੂਰਨ caps = 0;

	ਜੇ (max < 0)
		max = 0;

	uvalue = ਮੁੱਲ;

	ਜੇ(!(flags & DP_F_UNSIGNED)) {
		ਜੇ( ਮੁੱਲ < 0 ) {
			signvalue = '-';
			uvalue = -ਮੁੱਲ;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (flags & DP_F_PLUS)  /* Do a sign (+/i) */
				signvalue = '+';
			ਨਹੀਂਤਾਂ ਜੇ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

	ਜੇ (flags & DP_F_ਉੱਪਰ) caps = 1; /* Should characters be upper case? */

	ਕਰੋ {
		convert[ਰੱਖੋ++] =
			(caps? "0123456789ABCDEF":"0123456789abcdef")
			[uvalue % (ਬਿਨਾਨਿਸ਼ਾਨੀ)ਅਧਾਰ  ];
		uvalue = (uvalue / (ਬਿਨਾਨਿਸ਼ਾਨੀ)ਅਧਾਰ );
	} ਜਦੋਂ(uvalue && (ਰੱਖੋ < 20));
	ਜੇ (ਰੱਖੋ == 20) ਰੱਖੋ--;
	convert[ਰੱਖੋ] = 0;

	zpadlen = max - ਰੱਖੋ;
	spadlen = min - MAX (max, ਰੱਖੋ) - (signvalue ? 1 : 0);
	ਜੇ (zpadlen < 0) zpadlen = 0;
	ਜੇ (spadlen < 0) spadlen = 0;
	ਜੇ (flags & DP_F_ZERO) {
		zpadlen = MAX(zpadlen, spadlen);
		spadlen = 0;
	}
	ਜੇ (flags & DP_F_MINUS)
		spadlen = -spadlen; /* Left Justifty */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SNPRINTF
	ਲਿਖੋ("zpad: %d, spad: %d, min: %d, max: %d, place: %d\n",
	    zpadlen, spadlen, min, max, ਰੱਖੋ);
#ਜੇ_ਅੰਤ

	/* Spaces */
	ਜਦੋਂ (spadlen > 0) {
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, ' ');
		--spadlen;
	}

	/* Sign */
	ਜੇ (signvalue)
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, signvalue);

	/* Zeros */
	ਜੇ (zpadlen > 0) {
		ਜਦੋਂ (zpadlen > 0) {
			DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, '0');
			--zpadlen;
		}
	}

	/* Digits */
	ਜਦੋਂ (ਰੱਖੋ > 0) {
		--ਰੱਖੋ;
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, convert[ਰੱਖੋ]);
	}

	/* Left Justified spaces */
	ਜਦੋਂ (spadlen < 0) {
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, ' ');
		++spadlen;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ LDOUBLE abs_val(LDOUBLE ਮੁੱਲ)
{
	LDOUBLE ਨਤੀਜਾ = ਮੁੱਲ;

	ਜੇ (ਮੁੱਲ < 0)
		ਨਤੀਜਾ = -ਮੁੱਲ;

	ਵਾਪਸ ਨਤੀਜਾ;
}

ਸਥਿਰ LDOUBLE POW10(ਪੂਰਨ val)
{
	LDOUBLE ਨਤੀਜਾ = 1;

	ਜਦੋਂ (val) {
		ਨਤੀਜਾ *= 10;
		val--;
	}

	ਵਾਪਸ ਨਤੀਜਾ;
}

ਸਥਿਰ LLONG ਗੇੜਾ_2(LDOUBLE ਮੁੱਲ)
{
	LLONG intpart;

	intpart = (LLONG)ਮੁੱਲ;
	ਮੁੱਲ = ਮੁੱਲ - intpart;
	ਜੇ (ਮੁੱਲ >= 0.5) intpart++;

	ਵਾਪਸ intpart;
}

/* a replacement for modf that doesn't need the math library. Should
   be portable, but slow */
ਸਥਿਰ ਦੁੱਗਣਾ my_modf(ਦੁੱਗਣਾ x0, ਦੁੱਗਣਾ *iptr)
{
	ਪੂਰਨ i;
	ਲੰਮਾ l;
	ਦੁੱਗਣਾ x = x0;
	ਦੁੱਗਣਾ f = 1.0;

	ਲਈ (i=0;i<100;i++) {
		l = (ਲੰਮਾ)x;
		ਜੇ (l <= (x+1) && l >= (x-1)) ਰੋਕੋ;
		x *= 0.1;
		f *= 10.0;
	}

	ਜੇ (i == 100) {
		/*
		 * yikes! the number is beyond what we can handle.
		 * What do we do?
		 */
		(*iptr) = 0;
		ਵਾਪਸ 0;
	}

	ਜੇ (i != 0) {
		ਦੁੱਗਣਾ i2;
		ਦੁੱਗਣਾ ret;

		ret = my_modf(x0-l*f, &i2);
		(*iptr) = l*f + i2;
		ਵਾਪਸ ret;
	}

	(*iptr) = l;
	ਵਾਪਸ x - (*iptr);
}


ਸਥਿਰ ਪੂਰਨ
fmtfp (ਅੱਖਰ *ਬਫਰ, ਮਾਪ_t *currlen, ਮਾਪ_t maxlen,
    LDOUBLE fvalue, ਪੂਰਨ min, ਪੂਰਨ max, ਪੂਰਨ flags)
{
	ਪੂਰਨ signvalue = 0;
	ਦੁੱਗਣਾ ufvalue;
	ਅੱਖਰ iconvert[311];
	ਅੱਖਰ fconvert[311];
	ਪੂਰਨ iplace = 0;
	ਪੂਰਨ fplace = 0;
	ਪੂਰਨ padlen = 0; /* amount to pad */
	ਪੂਰਨ zpadlen = 0;
#ਜੇ 0
	ਪੂਰਨ caps = 0;
#ਜੇ_ਅੰਤ
	ਪੂਰਨ idx;
	ਦੁੱਗਣਾ intpart;
	ਦੁੱਗਣਾ fracpart;
	ਦੁੱਗਣਾ ਆਰਜ਼ੀ;

	/*
	 * AIX manpage says the default is 0, but Solaris says the default
	 * is 6, and sprintf on AIX defaults to 6
	 */
	ਜੇ (max < 0)
		max = 6;

	ufvalue = abs_val (fvalue);

	ਜੇ (fvalue < 0) {
		signvalue = '-';
	} ਨਹੀਂਤਾਂ {
		ਜੇ (flags & DP_F_PLUS) { /* Do a sign (+/i) */
			signvalue = '+';
		} ਨਹੀਂਤਾਂ {
			ਜੇ (flags & DP_F_SPACE)
				signvalue = ' ';
		}
	}

#ਜੇ 0
	ਜੇ (flags & DP_F_ਉੱਪਰ) caps = 1; /* Should characters be upper case? */
#ਜੇ_ਅੰਤ

#ਜੇ 0
	 ਜੇ (max == 0) ufvalue += 0.5; /* if max = 0 we must round */
#ਜੇ_ਅੰਤ

	/*
	 * Sorry, we only support 16 digits past the decimal because of our
	 * conversion method
	 */
	ਜੇ (max > 16)
		max = 16;

	/* We "cheat" by converting the fractional part to integer by
	 * multiplying by a factor of 10
	 */

	ਆਰਜ਼ੀ = ufvalue;
	my_modf(ਆਰਜ਼ੀ, &intpart);

	fracpart = ਗੇੜਾ_2((POW10(max)) * (ufvalue - intpart));

	ਜੇ (fracpart >= POW10(max)) {
		intpart++;
		fracpart -= POW10(max);
	}

	/* Convert integer part */
	ਕਰੋ {
		ਆਰਜ਼ੀ = intpart*0.1;
		my_modf(ਆਰਜ਼ੀ, &intpart);
		idx = (ਪੂਰਨ) ((ਆਰਜ਼ੀ -intpart +0.05)* 10.0);
		/* idx = (int) (((double)(temp*0.1) -intpart +0.05) *10.0); */
		/* printf ("%llf, %f, %x\n", temp, intpart, idx); */
		iconvert[iplace++] = "0123456789"[idx];
	} ਜਦੋਂ (intpart && (iplace < 311));
	ਜੇ (iplace == 311) iplace--;
	iconvert[iplace] = 0;

	/* Convert fractional part */
	ਜੇ (fracpart)
	{
		ਕਰੋ {
			ਆਰਜ਼ੀ = fracpart*0.1;
			my_modf(ਆਰਜ਼ੀ, &fracpart);
			idx = (ਪੂਰਨ) ((ਆਰਜ਼ੀ -fracpart +0.05)* 10.0);
			/* idx = (int) ((((temp/10) -fracpart) +0.05) *10); */
			/* printf ("%lf, %lf, %ld\n", temp, fracpart, idx ); */
			fconvert[fplace++] = "0123456789"[idx];
		} ਜਦੋਂ(fracpart && (fplace < 311));
		ਜੇ (fplace == 311) fplace--;
	}
	fconvert[fplace] = 0;

	/* -1 for decimal point, another -1 if we are printing a sign */
	padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
	zpadlen = max - fplace;
	ਜੇ (zpadlen < 0) zpadlen = 0;
	ਜੇ (padlen < 0)
		padlen = 0;
	ਜੇ (flags & DP_F_MINUS)
		padlen = -padlen; /* Left Justifty */

	ਜੇ ((flags & DP_F_ZERO) && (padlen > 0)) {
		ਜੇ (signvalue) {
			DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, signvalue);
			--padlen;
			signvalue = 0;
		}
		ਜਦੋਂ (padlen > 0) {
			DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, '0');
			--padlen;
		}
	}
	ਜਦੋਂ (padlen > 0) {
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, ' ');
		--padlen;
	}
	ਜੇ (signvalue)
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, signvalue);

	ਜਦੋਂ (iplace > 0) {
		--iplace;
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, iconvert[iplace]);
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SNPRINTF
	ਲਿਖੋ("fmtfp: fplace=%d zpadlen=%d\n", fplace, zpadlen);
#ਜੇ_ਅੰਤ

	/*
	 * Decimal point.  This should probably use locale to find the correct
	 * char to print out.
	 */
	ਜੇ (max > 0) {
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, '.');

		ਜਦੋਂ (zpadlen > 0) {
			DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, '0');
			--zpadlen;
		}

		ਜਦੋਂ (fplace > 0) {
			--fplace;
			DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, fconvert[fplace]);
		}
	}

	ਜਦੋਂ (padlen < 0) {
		DOPR_OUTCH(ਬਫਰ, *currlen, maxlen, ' ');
		++padlen;
	}
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ /* !defined(HAVE_SNPRINTF) || !defined(HAVE_VSNPRINTF) */

#ਜੇ !defined(HAVE_VSNPRINTF)
ਪੂਰਨ
vsnprintf (ਅੱਖਰ *str, ਮਾਪ_t ਗਿਣਤੀ_2, ਅਚਲ ਅੱਖਰ *fmt, va_list ਦਲੀਲਾਂ)
{
	ਵਾਪਸ dopr(str, ਗਿਣਤੀ_2, fmt, ਦਲੀਲਾਂ);
}
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_SNPRINTF)
ਪੂਰਨ
snprintf(ਅੱਖਰ *str, ਮਾਪ_t ਗਿਣਤੀ_2, SNPRINTF_CONST ਅੱਖਰ *fmt, ...)
{
	ਮਾਪ_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, ਗਿਣਤੀ_2, fmt, ap);
	va_end(ap);
	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ
