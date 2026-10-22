/*	$OpenBSD: fnmatch.c,v 1.22 2020/03/13 03:25:45 djm Exp $	*/

/* Copyright (c) 2011, VMware, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the VMware, Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2008, 2016 Todd C. Miller <millert@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Authored by William A. Rowe Jr. <wrowe; apache.org, vmware.com>, April 2011
 *
 * Derived from The Open Group Base Specifications Issue 7, IEEE Std 1003.1-2008
 * as described in;
 *   http://pubs.opengroup.org/onlinepubs/9699919799/functions/fnmatch.html
 *
 * Filename pattern matches defined in section 2.13, "Pattern Matching Notation"
 * from chapter 2. "Shell Command Language"
 *   http://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_13
 * where; 1. A bracket expression starting with an unquoted <circumflex> '^'
 * character CONTINUES to specify a non-matching list; 2. an explicit <period> '.'
 * in a bracket expression matching list, e.g. "[.abc]" does NOT match a leading
 * <period> in a filename; 3. a <left-square-bracket> '[' which does not introduce
 * a valid bracket expression is treated as an ordinary character; 4. a differing
 * number of consecutive slashes within pattern and string will NOT match;
 * 5. a trailing '\' in FNM_ESCAPE mode is treated as an ordinary '\' character.
 *
 * Bracket expansion defined in section 9.3.5, "RE Bracket Expression",
 * from chapter 9, "Regular Expressions"
 *   http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html#tag_09_03_05
 * with no support for collating symbols, equivalence class expressions or
 * character class expressions.  A partial range expression with a leading
 * hyphen following a valid range expression will match only the ordinary
 * <hyphen> and the ending character (e.g. "[a-m-z]" will match characters
 * 'a' through 'm', a <hyphen> '-', or a 'z').
 *
 * Supports BSD extensions FNM_LEADING_DIR to match pattern to the end of one
 * path segment of string, and FNM_CASEFOLD to ignore alpha case.
 *
 * NOTE: Only POSIX/C single byte locales are correctly supported at this time.
 * Notably, non-POSIX locales with FNM_CASEFOLD produce undefined results,
 * particularly in ranges of mixed case (e.g. "[A-z]") or spanning alpha and
 * nonalpha characters within a range.
 *
 * XXX comments below indicate porting required for multi-byte character sets
 * and non-POSIX locale collation orders; requires mbr* APIs to track shift
 * state of pattern and string (rewinding pattern and string repeatedly).
 *
 * Certain parts of the code assume 0x00-0x3F are unique with any MBCS (e.g.
 * UTF-8, SHIFT-JIS, etc).  Any implementation allowing '\' as an alternate
 * path delimiter must be aware that 0x5C is NOT unique within SHIFT-JIS.
 */

/* OPENBSD ORIGINAL: lib/libc/gen/fnmatch.c */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FNMATCH

#ਅਨ੍ਤਰ੍ਭਾਵ <fnmatch.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "charclass.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	RANGE_ਮੇਲ	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	RANGE_NOMATCH	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	RANGE_ERROR	(-1)

ਸਥਿਰ ਪੂਰਨ
classmatch(ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ, ਅੱਖਰ test, ਪੂਰਨ foldcase, ਅਚਲ ਅੱਖਰ **ep)
{
	ਅਚਲ ਅੱਖਰ * ਅਚਲ mismatch = ਨਮੂਨਾ;
	ਅਚਲ ਅੱਖਰ *colon;
	ਬਣਤਰ cclass *cc;
	ਪੂਰਨ rval = RANGE_NOMATCH;
	ਮਾਪ_t len;

	ਜੇ (ਨਮੂਨਾ[0] != '[' || ਨਮੂਨਾ[1] != ':') {
		*ep = mismatch;
		ਵਾਪਸ RANGE_ERROR;
	}
	ਨਮੂਨਾ += 2;

	ਜੇ ((colon = strchr(ਨਮੂਨਾ, ':')) == ਨਿਰਾ || colon[1] != ']') {
		*ep = mismatch;
		ਵਾਪਸ RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (ਮਾਪ_t)(colon - ਨਮੂਨਾ);

	ਜੇ (foldcase && ਲੜੀ_ਤੁਲਨਾ(ਨਮੂਨਾ, "upper:]", 7) == 0)
		ਨਮੂਨਾ = "lower:]";
	ਲਈ (cc = cclasses; cc->name != ਨਿਰਾ; cc++) {
		ਜੇ (!ਲੜੀ_ਤੁਲਨਾ(ਨਮੂਨਾ, cc->name, len) && cc->name[len] == '\0') {
			ਜੇ (cc->isctype((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)test))
				rval = RANGE_ਮੇਲ;
			ਰੋਕੋ;
		}
	}
	ਜੇ (cc->name == ਨਿਰਾ) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	ਵਾਪਸ rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
ਸਥਿਰ ਪੂਰਨ fnmatch_ch(ਅਚਲ ਅੱਖਰ **ਨਮੂਨਾ, ਅਚਲ ਅੱਖਰ **string, ਪੂਰਨ flags)
{
	ਅਚਲ ਅੱਖਰ * ਅਚਲ mismatch = *ਨਮੂਨਾ;
	ਅਚਲ ਪੂਰਨ nocase = !!(flags & FNM_CASEFOLD);
	ਅਚਲ ਪੂਰਨ escape = !(flags & FNM_NOESCAPE);
	ਅਚਲ ਪੂਰਨ slash = !!(flags & FNM_PATHNAME);
	ਪੂਰਨ ਨਤੀਜਾ = FNM_NOMATCH;
	ਅਚਲ ਅੱਖਰ *startch;
	ਪੂਰਨ negate;

	ਜੇ (**ਨਮੂਨਾ == '[') {
		++*ਨਮੂਨਾ;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**ਨਮੂਨਾ == '!') || (**ਨਮੂਨਾ == '^');
		ਜੇ (negate)
			++*ਨਮੂਨਾ;

		/* ']' is an ordinary char at the start of the range pattern */
		ਜੇ (**ਨਮੂਨਾ == ']')
			ਜਾਓ leadingclosebrace;

		ਜਦੋਂ (**ਨਮੂਨਾ) {
			ਜੇ (**ਨਮੂਨਾ == ']') {
				++*ਨਮੂਨਾ;
				/* XXX: Fix for MBCS character width */
				++*string;
				ਵਾਪਸ (ਨਤੀਜਾ ^ negate);
			}

			ਜੇ (escape && (**ਨਮੂਨਾ == '\\')) {
				++*ਨਮੂਨਾ;

				/* Patterns must terminate with ']', not EOS */
				ਜੇ (!**ਨਮੂਨਾ)
					ਰੋਕੋ;
			}

			/* Patterns must terminate with ']' not '/' */
			ਜੇ (slash && (**ਨਮੂਨਾ == '/'))
				ਰੋਕੋ;

			/* Match character classes. */
			ਚੋਣ (classmatch(*ਨਮੂਨਾ, **string, nocase, ਨਮੂਨਾ)) {
			ਹਾਲਤ RANGE_ਮੇਲ:
				ਨਤੀਜਾ = 0;
				ਜਾਰੀ;
			ਹਾਲਤ RANGE_NOMATCH:
				/* Valid character class but no match. */
				ਜਾਰੀ;
			ਮੂਲ:
				/* Not a valid character class. */
				ਰੋਕੋ;
			}
			ਜੇ (!**ਨਮੂਨਾ)
				ਰੋਕੋ;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			ਜੇ (((*ਨਮੂਨਾ)[1] == '-') && ((*ਨਮੂਨਾ)[2] != ']')) {
				startch = *ਨਮੂਨਾ;
				*ਨਮੂਨਾ += (escape && ((*ਨਮੂਨਾ)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				ਜੇ (!**ਨਮੂਨਾ || (slash && (**ਨਮੂਨਾ == '/')))
					ਰੋਕੋ;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				ਜੇ ((**string >= *startch) && (**string <= **ਨਮੂਨਾ))
					ਨਤੀਜਾ = 0;
				ਨਹੀਂਤਾਂ ਜੇ (nocase &&
				    (isupper((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**string) ||
				     isupper((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*startch) ||
				     isupper((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**ਨਮੂਨਾ)) &&
				    (tolower((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**string) >=
				     tolower((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*startch)) &&
				    (tolower((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**string) <=
				     tolower((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**ਨਮੂਨਾ)))
					ਨਤੀਜਾ = 0;

				++*ਨਮੂਨਾ;
				ਜਾਰੀ;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			ਜੇ ((**string == **ਨਮੂਨਾ))
				ਨਤੀਜਾ = 0;
			ਨਹੀਂਤਾਂ ਜੇ (nocase && (isupper((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**string) ||
			    isupper((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**ਨਮੂਨਾ)) &&
			    (tolower((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**string) ==
			    tolower((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**ਨਮੂਨਾ)))
				ਨਤੀਜਾ = 0;

			++*ਨਮੂਨਾ;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*ਨਮੂਨਾ = mismatch;
		ਨਤੀਜਾ = FNM_NOMATCH;
	} ਨਹੀਂਤਾਂ ਜੇ (**ਨਮੂਨਾ == '?') {
		/* Optimize '?' match before unescaping **pattern */
		ਜੇ (!**string || (slash && (**string == '/')))
			ਵਾਪਸ FNM_NOMATCH;
		ਨਤੀਜਾ = 0;
		ਜਾਓ fnmatch_ch_success;
	} ਨਹੀਂਤਾਂ ਜੇ (escape && (**ਨਮੂਨਾ == '\\') && (*ਨਮੂਨਾ)[1]) {
		++*ਨਮੂਨਾ;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	ਜੇ (**string == **ਨਮੂਨਾ)
		ਨਤੀਜਾ = 0;
	ਨਹੀਂਤਾਂ ਜੇ (nocase && (isupper((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**string) ||
	    isupper((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**ਨਮੂਨਾ)) &&
	    (tolower((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**string) ==
	    tolower((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)**ਨਮੂਨਾ)))
		ਨਤੀਜਾ = 0;

	/* Refuse to advance over trailing slash or NULs */
	ਜੇ (**string == '\0' || **ਨਮੂਨਾ == '\0' ||
	    (slash && ((**string == '/') || (**ਨਮੂਨਾ == '/'))))
		ਵਾਪਸ ਨਤੀਜਾ;

fnmatch_ch_success:
	++*ਨਮੂਨਾ;
	++*string;
	ਵਾਪਸ ਨਤੀਜਾ;
}


ਪੂਰਨ fnmatch(ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ, ਅਚਲ ਅੱਖਰ *string, ਪੂਰਨ flags)
{
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ dummystring[2] = {' ', 0};
	ਅਚਲ ਪੂਰਨ escape = !(flags & FNM_NOESCAPE);
	ਅਚਲ ਪੂਰਨ slash = !!(flags & FNM_PATHNAME);
	ਅਚਲ ਪੂਰਨ leading_dir = !!(flags & FNM_LEADING_DIR);
	ਅਚਲ ਅੱਖਰ *dummyptr, *matchptr, *strendseg;
	ਪੂਰਨ wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	ਅਚਲ ਅੱਖਰ *strstartseg = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *mismatch = ਨਿਰਾ;
	ਪੂਰਨ matchlen = 0;

	ਜੇ (*ਨਮੂਨਾ == '*')
		ਜਾਓ firstsegment;

	ਜਦੋਂ (*ਨਮੂਨਾ && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		ਜੇ (slash && escape && (*ਨਮੂਨਾ == '\\') && (ਨਮੂਨਾ[1] == '/'))
			++ਨਮੂਨਾ;
		ਜੇ (slash && (*ਨਮੂਨਾ == '/') && (*string == '/')) {
			++ਨਮੂਨਾ;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		ਜੇ ((flags & FNM_PERIOD) && (*string == '.')) {
		    ਜੇ (*ਨਮੂਨਾ == '.')
			    ++ਨਮੂਨਾ;
		    ਨਹੀਂਤਾਂ ਜੇ (escape && (*ਨਮੂਨਾ == '\\') && (ਨਮੂਨਾ[1] == '.'))
			    ਨਮੂਨਾ += 2;
		    ਨਹੀਂਤਾਂ
			    ਵਾਪਸ FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		ਜੇ (slash) {
			strendseg = strchr(string, '/');
			ਜੇ (!strendseg)
				strendseg = strchr(string, '\0');
		} ਨਹੀਂਤਾਂ {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		ਜਦੋਂ (*ਨਮੂਨਾ) {
			ਜੇ ((string > strendseg) ||
			    ((string == strendseg) && (*ਨਮੂਨਾ != '*')))
				ਰੋਕੋ;

			ਜੇ (slash && ((*ਨਮੂਨਾ == '/') ||
			    (escape && (*ਨਮੂਨਾ == '\\') && (ਨਮੂਨਾ[1] == '/'))))
				ਰੋਕੋ;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			ਲਈ (wild = 0; (*ਨਮੂਨਾ == '*') || (*ਨਮੂਨਾ == '?'); ++ਨਮੂਨਾ) {
				ਜੇ (*ਨਮੂਨਾ == '*') {
					wild = 1;
				} ਨਹੀਂਤਾਂ ਜੇ (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				ਨਹੀਂਤਾਂ {  /* (string >= strendseg) && (*pattern == '?') */
					ਵਾਪਸ FNM_NOMATCH;
				}
			}

			ਜੇ (wild) {
				strstartseg = string;
				mismatch = ਨਮੂਨਾ;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				ਲਈ (matchptr = ਨਮੂਨਾ, matchlen = 0; 1; ++matchlen) {
					ਜੇ ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						ਜੇ (string + matchlen > strendseg)
							ਵਾਪਸ FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						ਰੋਕੋ;
					}

					ਜੇ (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						ਜੇ (string + matchlen > strendseg)
							ਵਾਪਸ FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						ਰੋਕੋ;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					ਜੇ (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} ਨਹੀਂਤਾਂ ਜੇ (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} ਨਹੀਂਤਾਂ {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			ਜਦੋਂ (*ਨਮੂਨਾ && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				ਜੇ (*ਨਮੂਨਾ == '*')
					ਰੋਕੋ;

				ਜੇ (slash && ((*string == '/') ||
				    (*ਨਮੂਨਾ == '/') || (escape &&
				    (*ਨਮੂਨਾ == '\\') && (ਨਮੂਨਾ[1] == '/'))))
					ਰੋਕੋ;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				ਜੇ (!fnmatch_ch(&ਨਮੂਨਾ, &string, flags))
					ਜਾਰੀ;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				ਜੇ (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					ਜੇ (string + matchlen > strendseg)
						ਵਾਪਸ FNM_NOMATCH;

					ਨਮੂਨਾ = mismatch;
					ਜਾਰੀ;
				} ਨਹੀਂਤਾਂ
					ਵਾਪਸ FNM_NOMATCH;
			}
		}

		ਜੇ (*string && !((slash || leading_dir) && (*string == '/')))
			ਵਾਪਸ FNM_NOMATCH;

		ਜੇ (*ਨਮੂਨਾ && !(slash && ((*ਨਮੂਨਾ == '/') ||
		    (escape && (*ਨਮੂਨਾ == '\\') && (ਨਮੂਨਾ[1] == '/')))))
			ਵਾਪਸ FNM_NOMATCH;

		ਜੇ (leading_dir && !*ਨਮੂਨਾ && *string == '/')
			ਵਾਪਸ 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	ਜੇ (!*string && !*ਨਮੂਨਾ)
		ਵਾਪਸ 0;

	/* Pattern didn't match to the end of string. */
	ਵਾਪਸ FNM_NOMATCH;
}
#ਜੇ_ਅੰਤ /* HAVE_FNMATCH */
