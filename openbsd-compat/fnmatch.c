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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ifndef HAVE_FNMATCH

#ଅନ୍ତର୍ଭାଵ <fnmatch.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <ctype.h>

#ଅନ୍ତର୍ଭାଵ "charclass.h"

#define	RANGE_MATCH	1
#define	RANGE_NOMATCH	0
#define	RANGE_ERROR	(-1)

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
classmatch(ଅଚଳ ଅକ୍ଷର *pattern, ଅକ୍ଷର test, ପୂର୍ଣ୍ଣସଂଖ୍ୟା foldcase, ଅଚଳ ଅକ୍ଷର **ep)
{
	ଅଚଳ ଅକ୍ଷର * ଅଚଳ mismatch = pattern;
	ଅଚଳ ଅକ୍ଷର *colon;
	ସଂରଚନା cclass *cc;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rval = RANGE_NOMATCH;
	size_t len;

	ଯଦି (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		ଫେରନ୍ତୁ RANGE_ERROR;
	}
	pattern += 2;

	ଯଦି ((colon = strchr(pattern, ':')) == ଖାଲି || colon[1] != ']') {
		*ep = mismatch;
		ଫେରନ୍ତୁ RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	ଯଦି (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	ପାଇଁ (cc = cclasses; cc->name != ଖାଲି; cc++) {
		ଯଦି (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			ଯଦି (cc->isctype((unsigned ଅକ୍ଷର)test))
				rval = RANGE_MATCH;
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (cc->name == ଖାଲି) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	ଫେରନ୍ତୁ rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା fnmatch_ch(ଅଚଳ ଅକ୍ଷର **pattern, ଅଚଳ ଅକ୍ଷର **string, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ଅଚଳ ଅକ୍ଷର * ଅଚଳ mismatch = *pattern;
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା nocase = !!(flags & FNM_CASEFOLD);
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା escape = !(flags & FNM_NOESCAPE);
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା slash = !!(flags & FNM_PATHNAME);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା result = FNM_NOMATCH;
	ଅଚଳ ଅକ୍ଷର *startch;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା negate;

	ଯଦି (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		ଯଦି (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		ଯଦି (**pattern == ']')
			ଯାଅ leadingclosebrace;

		ଯେତେବେଳେ (**pattern) {
			ଯଦି (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				ଫେରନ୍ତୁ (result ^ negate);
			}

			ଯଦି (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				ଯଦି (!**pattern)
					ଭାଙ୍ଗ;
			}

			/* Patterns must terminate with ']' not '/' */
			ଯଦି (slash && (**pattern == '/'))
				ଭାଙ୍ଗ;

			/* Match character classes. */
			ବାଛ (classmatch(*pattern, **string, nocase, pattern)) {
			ସ୍ଥିତି RANGE_MATCH:
				result = 0;
				ଜାରି;
			ସ୍ଥିତି RANGE_NOMATCH:
				/* Valid character class but no match. */
				ଜାରି;
			ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
				/* Not a valid character class. */
				ଭାଙ୍ଗ;
			}
			ଯଦି (!**pattern)
				ଭାଙ୍ଗ;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			ଯଦି (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				ଯଦି (!**pattern || (slash && (**pattern == '/')))
					ଭାଙ୍ଗ;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				ଯଦି ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				ଅନ୍ୟଥା ଯଦି (nocase &&
				    (isupper((unsigned ଅକ୍ଷର)**string) ||
				     isupper((unsigned ଅକ୍ଷର)*startch) ||
				     isupper((unsigned ଅକ୍ଷର)**pattern)) &&
				    (tolower((unsigned ଅକ୍ଷର)**string) >=
				     tolower((unsigned ଅକ୍ଷର)*startch)) &&
				    (tolower((unsigned ଅକ୍ଷର)**string) <=
				     tolower((unsigned ଅକ୍ଷର)**pattern)))
					result = 0;

				++*pattern;
				ଜାରି;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			ଯଦି ((**string == **pattern))
				result = 0;
			ଅନ୍ୟଥା ଯଦି (nocase && (isupper((unsigned ଅକ୍ଷର)**string) ||
			    isupper((unsigned ଅକ୍ଷର)**pattern)) &&
			    (tolower((unsigned ଅକ୍ଷର)**string) ==
			    tolower((unsigned ଅକ୍ଷର)**pattern)))
				result = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		result = FNM_NOMATCH;
	} ଅନ୍ୟଥା ଯଦି (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		ଯଦି (!**string || (slash && (**string == '/')))
			ଫେରନ୍ତୁ FNM_NOMATCH;
		result = 0;
		ଯାଅ fnmatch_ch_success;
	} ଅନ୍ୟଥା ଯଦି (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	ଯଦି (**string == **pattern)
		result = 0;
	ଅନ୍ୟଥା ଯଦି (nocase && (isupper((unsigned ଅକ୍ଷର)**string) ||
	    isupper((unsigned ଅକ୍ଷର)**pattern)) &&
	    (tolower((unsigned ଅକ୍ଷର)**string) ==
	    tolower((unsigned ଅକ୍ଷର)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	ଯଦି (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		ଫେରନ୍ତୁ result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	ଫେରନ୍ତୁ result;
}


ପୂର୍ଣ୍ଣସଂଖ୍ୟା fnmatch(ଅଚଳ ଅକ୍ଷର *pattern, ଅଚଳ ଅକ୍ଷର *string, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ସ୍ଥିର ଅଚଳ ଅକ୍ଷର dummystring[2] = {' ', 0};
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା escape = !(flags & FNM_NOESCAPE);
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା slash = !!(flags & FNM_PATHNAME);
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା leading_dir = !!(flags & FNM_LEADING_DIR);
	ଅଚଳ ଅକ୍ଷର *dummyptr, *matchptr, *strendseg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	ଅଚଳ ଅକ୍ଷର *strstartseg = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *mismatch = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା matchlen = 0;

	ଯଦି (*pattern == '*')
		ଯାଅ firstsegment;

	ଯେତେବେଳେ (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		ଯଦି (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		ଯଦି (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		ଯଦି ((flags & FNM_PERIOD) && (*string == '.')) {
		    ଯଦି (*pattern == '.')
			    ++pattern;
		    ଅନ୍ୟଥା ଯଦି (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    ଅନ୍ୟଥା
			    ଫେରନ୍ତୁ FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		ଯଦି (slash) {
			strendseg = strchr(string, '/');
			ଯଦି (!strendseg)
				strendseg = strchr(string, '\0');
		} ଅନ୍ୟଥା {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		ଯେତେବେଳେ (*pattern) {
			ଯଦି ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				ଭାଙ୍ଗ;

			ଯଦି (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				ଭାଙ୍ଗ;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			ପାଇଁ (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				ଯଦି (*pattern == '*') {
					wild = 1;
				} ଅନ୍ୟଥା ଯଦି (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				ଅନ୍ୟଥା {  /* (string >= strendseg) && (*pattern == '?') */
					ଫେରନ୍ତୁ FNM_NOMATCH;
				}
			}

			ଯଦି (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				ପାଇଁ (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					ଯଦି ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						ଯଦି (string + matchlen > strendseg)
							ଫେରନ୍ତୁ FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						ଭାଙ୍ଗ;
					}

					ଯଦି (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						ଯଦି (string + matchlen > strendseg)
							ଫେରନ୍ତୁ FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						ଭାଙ୍ଗ;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					ଯଦି (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} ଅନ୍ୟଥା ଯଦି (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} ଅନ୍ୟଥା {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			ଯେତେବେଳେ (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				ଯଦି (*pattern == '*')
					ଭାଙ୍ଗ;

				ଯଦି (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					ଭାଙ୍ଗ;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				ଯଦି (!fnmatch_ch(&pattern, &string, flags))
					ଜାରି;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				ଯଦି (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					ଯଦି (string + matchlen > strendseg)
						ଫେରନ୍ତୁ FNM_NOMATCH;

					pattern = mismatch;
					ଜାରି;
				} ଅନ୍ୟଥା
					ଫେରନ୍ତୁ FNM_NOMATCH;
			}
		}

		ଯଦି (*string && !((slash || leading_dir) && (*string == '/')))
			ଫେରନ୍ତୁ FNM_NOMATCH;

		ଯଦି (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			ଫେରନ୍ତୁ FNM_NOMATCH;

		ଯଦି (leading_dir && !*pattern && *string == '/')
			ଫେରନ୍ତୁ 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	ଯଦି (!*string && !*pattern)
		ଫେରନ୍ତୁ 0;

	/* Pattern didn't match to the end of string. */
	ଫେରନ୍ତୁ FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
