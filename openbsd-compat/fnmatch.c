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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FNMATCH

#ಅನ್ತರ್ಭಾವ <fnmatch.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>

#ಅನ್ತರ್ಭಾವ "charclass.h"

#ವ್ಯಾಖ್ಯಾನಿಸು	RANGE_ಹೊಂದಿಕೆ	1
#ವ್ಯಾಖ್ಯಾನಿಸು	RANGE_NOMATCH	0
#ವ್ಯಾಖ್ಯಾನಿಸು	RANGE_ERROR	(-1)

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
classmatch(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ, ಅಕ್ಷರ test, ಪೂರ್ಣಾಂಕ foldcase, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **ep)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ mismatch = ನಮೂನೆ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *colon;
	ರಚನೆ cclass *cc;
	ಪೂರ್ಣಾಂಕ rval = RANGE_NOMATCH;
	ಗಾತ್ರ_t len;

	ಆದರೆ (ನಮೂನೆ[0] != '[' || ನಮೂನೆ[1] != ':') {
		*ep = mismatch;
		ಹಿಂತಿರುಗಿ RANGE_ERROR;
	}
	ನಮೂನೆ += 2;

	ಆದರೆ ((colon = strchr(ನಮೂನೆ, ':')) == ಖಾಲಿ || colon[1] != ']') {
		*ep = mismatch;
		ಹಿಂತಿರುಗಿ RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (ಗಾತ್ರ_t)(colon - ನಮೂನೆ);

	ಆದರೆ (foldcase && ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ನಮೂನೆ, "upper:]", 7) == 0)
		ನಮೂನೆ = "lower:]";
	ಗಾಗಿ (cc = cclasses; cc->name != ಖಾಲಿ; cc++) {
		ಆದರೆ (!ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ನಮೂನೆ, cc->name, len) && cc->name[len] == '\0') {
			ಆದರೆ (cc->isctype((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)test))
				rval = RANGE_ಹೊಂದಿಕೆ;
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (cc->name == ಖಾಲಿ) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	ಹಿಂತಿರುಗಿ rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ fnmatch_ch(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **ನಮೂನೆ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **string, ಪೂರ್ಣಾಂಕ flags)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ mismatch = *ನಮೂನೆ;
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ nocase = !!(flags & FNM_CASEFOLD);
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ escape = !(flags & FNM_NOESCAPE);
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ slash = !!(flags & FNM_PATHNAME);
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ = FNM_NOMATCH;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *startch;
	ಪೂರ್ಣಾಂಕ negate;

	ಆದರೆ (**ನಮೂನೆ == '[') {
		++*ನಮೂನೆ;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**ನಮೂನೆ == '!') || (**ನಮೂನೆ == '^');
		ಆದರೆ (negate)
			++*ನಮೂನೆ;

		/* ']' is an ordinary char at the start of the range pattern */
		ಆದರೆ (**ನಮೂನೆ == ']')
			ಹೋಗು leadingclosebrace;

		ಆಗ (**ನಮೂನೆ) {
			ಆದರೆ (**ನಮೂನೆ == ']') {
				++*ನಮೂನೆ;
				/* XXX: Fix for MBCS character width */
				++*string;
				ಹಿಂತಿರುಗಿ (ಫಲಿತಾಂಶ ^ negate);
			}

			ಆದರೆ (escape && (**ನಮೂನೆ == '\\')) {
				++*ನಮೂನೆ;

				/* Patterns must terminate with ']', not EOS */
				ಆದರೆ (!**ನಮೂನೆ)
					ನಿಲ್ಲಿಸು;
			}

			/* Patterns must terminate with ']' not '/' */
			ಆದರೆ (slash && (**ನಮೂನೆ == '/'))
				ನಿಲ್ಲಿಸು;

			/* Match character classes. */
			ಆಯ್ಕೆ (classmatch(*ನಮೂನೆ, **string, nocase, ನಮೂನೆ)) {
			ಸ್ಥಿತಿ RANGE_ಹೊಂದಿಕೆ:
				ಫಲಿತಾಂಶ = 0;
				ಮುಂದುವರಿ;
			ಸ್ಥಿತಿ RANGE_NOMATCH:
				/* Valid character class but no match. */
				ಮುಂದುವರಿ;
			ಪೂರ್ವನಿಯೋಜಿತ:
				/* Not a valid character class. */
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (!**ನಮೂನೆ)
				ನಿಲ್ಲಿಸು;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			ಆದರೆ (((*ನಮೂನೆ)[1] == '-') && ((*ನಮೂನೆ)[2] != ']')) {
				startch = *ನಮೂನೆ;
				*ನಮೂನೆ += (escape && ((*ನಮೂನೆ)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				ಆದರೆ (!**ನಮೂನೆ || (slash && (**ನಮೂನೆ == '/')))
					ನಿಲ್ಲಿಸು;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				ಆದರೆ ((**string >= *startch) && (**string <= **ನಮೂನೆ))
					ಫಲಿತಾಂಶ = 0;
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (nocase &&
				    (isupper((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**string) ||
				     isupper((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*startch) ||
				     isupper((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**ನಮೂನೆ)) &&
				    (tolower((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**string) >=
				     tolower((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*startch)) &&
				    (tolower((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**string) <=
				     tolower((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**ನಮೂನೆ)))
					ಫಲಿತಾಂಶ = 0;

				++*ನಮೂನೆ;
				ಮುಂದುವರಿ;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			ಆದರೆ ((**string == **ನಮೂನೆ))
				ಫಲಿತಾಂಶ = 0;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (nocase && (isupper((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**string) ||
			    isupper((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**ನಮೂನೆ)) &&
			    (tolower((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**string) ==
			    tolower((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**ನಮೂನೆ)))
				ಫಲಿತಾಂಶ = 0;

			++*ನಮೂನೆ;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*ನಮೂನೆ = mismatch;
		ಫಲಿತಾಂಶ = FNM_NOMATCH;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (**ನಮೂನೆ == '?') {
		/* Optimize '?' match before unescaping **pattern */
		ಆದರೆ (!**string || (slash && (**string == '/')))
			ಹಿಂತಿರುಗಿ FNM_NOMATCH;
		ಫಲಿತಾಂಶ = 0;
		ಹೋಗು fnmatch_ch_success;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (escape && (**ನಮೂನೆ == '\\') && (*ನಮೂನೆ)[1]) {
		++*ನಮೂನೆ;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	ಆದರೆ (**string == **ನಮೂನೆ)
		ಫಲಿತಾಂಶ = 0;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (nocase && (isupper((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**string) ||
	    isupper((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**ನಮೂನೆ)) &&
	    (tolower((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**string) ==
	    tolower((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)**ನಮೂನೆ)))
		ಫಲಿತಾಂಶ = 0;

	/* Refuse to advance over trailing slash or NULs */
	ಆದರೆ (**string == '\0' || **ನಮೂನೆ == '\0' ||
	    (slash && ((**string == '/') || (**ನಮೂನೆ == '/'))))
		ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;

fnmatch_ch_success:
	++*ನಮೂನೆ;
	++*string;
	ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}


ಪೂರ್ಣಾಂಕ fnmatch(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *string, ಪೂರ್ಣಾಂಕ flags)
{
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ dummystring[2] = {' ', 0};
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ escape = !(flags & FNM_NOESCAPE);
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ slash = !!(flags & FNM_PATHNAME);
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ leading_dir = !!(flags & FNM_LEADING_DIR);
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *dummyptr, *matchptr, *strendseg;
	ಪೂರ್ಣಾಂಕ wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *strstartseg = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *mismatch = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ matchlen = 0;

	ಆದರೆ (*ನಮೂನೆ == '*')
		ಹೋಗು firstsegment;

	ಆಗ (*ನಮೂನೆ && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		ಆದರೆ (slash && escape && (*ನಮೂನೆ == '\\') && (ನಮೂನೆ[1] == '/'))
			++ನಮೂನೆ;
		ಆದರೆ (slash && (*ನಮೂನೆ == '/') && (*string == '/')) {
			++ನಮೂನೆ;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		ಆದರೆ ((flags & FNM_PERIOD) && (*string == '.')) {
		    ಆದರೆ (*ನಮೂನೆ == '.')
			    ++ನಮೂನೆ;
		    ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (escape && (*ನಮೂನೆ == '\\') && (ನಮೂನೆ[1] == '.'))
			    ನಮೂನೆ += 2;
		    ಇಲ್ಲದಿದ್ದರೆ
			    ಹಿಂತಿರುಗಿ FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		ಆದರೆ (slash) {
			strendseg = strchr(string, '/');
			ಆದರೆ (!strendseg)
				strendseg = strchr(string, '\0');
		} ಇಲ್ಲದಿದ್ದರೆ {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		ಆಗ (*ನಮೂನೆ) {
			ಆದರೆ ((string > strendseg) ||
			    ((string == strendseg) && (*ನಮೂನೆ != '*')))
				ನಿಲ್ಲಿಸು;

			ಆದರೆ (slash && ((*ನಮೂನೆ == '/') ||
			    (escape && (*ನಮೂನೆ == '\\') && (ನಮೂನೆ[1] == '/'))))
				ನಿಲ್ಲಿಸು;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			ಗಾಗಿ (wild = 0; (*ನಮೂನೆ == '*') || (*ನಮೂನೆ == '?'); ++ನಮೂನೆ) {
				ಆದರೆ (*ನಮೂನೆ == '*') {
					wild = 1;
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				ಇಲ್ಲದಿದ್ದರೆ {  /* (string >= strendseg) && (*pattern == '?') */
					ಹಿಂತಿರುಗಿ FNM_NOMATCH;
				}
			}

			ಆದರೆ (wild) {
				strstartseg = string;
				mismatch = ನಮೂನೆ;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				ಗಾಗಿ (matchptr = ನಮೂನೆ, matchlen = 0; 1; ++matchlen) {
					ಆದರೆ ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						ಆದರೆ (string + matchlen > strendseg)
							ಹಿಂತಿರುಗಿ FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						ನಿಲ್ಲಿಸು;
					}

					ಆದರೆ (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						ಆದರೆ (string + matchlen > strendseg)
							ಹಿಂತಿರುಗಿ FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						ನಿಲ್ಲಿಸು;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					ಆದರೆ (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} ಇಲ್ಲದಿದ್ದರೆ {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			ಆಗ (*ನಮೂನೆ && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				ಆದರೆ (*ನಮೂನೆ == '*')
					ನಿಲ್ಲಿಸು;

				ಆದರೆ (slash && ((*string == '/') ||
				    (*ನಮೂನೆ == '/') || (escape &&
				    (*ನಮೂನೆ == '\\') && (ನಮೂನೆ[1] == '/'))))
					ನಿಲ್ಲಿಸು;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				ಆದರೆ (!fnmatch_ch(&ನಮೂನೆ, &string, flags))
					ಮುಂದುವರಿ;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				ಆದರೆ (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					ಆದರೆ (string + matchlen > strendseg)
						ಹಿಂತಿರುಗಿ FNM_NOMATCH;

					ನಮೂನೆ = mismatch;
					ಮುಂದುವರಿ;
				} ಇಲ್ಲದಿದ್ದರೆ
					ಹಿಂತಿರುಗಿ FNM_NOMATCH;
			}
		}

		ಆದರೆ (*string && !((slash || leading_dir) && (*string == '/')))
			ಹಿಂತಿರುಗಿ FNM_NOMATCH;

		ಆದರೆ (*ನಮೂನೆ && !(slash && ((*ನಮೂನೆ == '/') ||
		    (escape && (*ನಮೂನೆ == '\\') && (ನಮೂನೆ[1] == '/')))))
			ಹಿಂತಿರುಗಿ FNM_NOMATCH;

		ಆದರೆ (leading_dir && !*ನಮೂನೆ && *string == '/')
			ಹಿಂತಿರುಗಿ 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	ಆದರೆ (!*string && !*ನಮೂನೆ)
		ಹಿಂತಿರುಗಿ 0;

	/* Pattern didn't match to the end of string. */
	ಹಿಂತಿರುಗಿ FNM_NOMATCH;
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FNMATCH */
