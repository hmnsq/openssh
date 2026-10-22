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

#அந்தர்பாவ "includes.h"
#ifndef HAVE_FNMATCH

#அந்தர்பாவ <fnmatch.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <ctype.h>

#அந்தர்பாவ "charclass.h"

#define	RANGE_MATCH	1
#define	RANGE_NOMATCH	0
#define	RANGE_ERROR	(-1)

நிலையான முழு
classmatch(மாறிலி எழுத்து *pattern, எழுத்து test, முழு foldcase, மாறிலி எழுத்து **ep)
{
	மாறிலி எழுத்து * மாறிலி mismatch = pattern;
	மாறிலி எழுத்து *colon;
	கட்டமைப்பு cclass *cc;
	முழு rval = RANGE_NOMATCH;
	size_t len;

	எனில் (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		திரும்பு RANGE_ERROR;
	}
	pattern += 2;

	எனில் ((colon = strchr(pattern, ':')) == வெற்று || colon[1] != ']') {
		*ep = mismatch;
		திரும்பு RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	எனில் (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	க்கு (cc = cclasses; cc->name != வெற்று; cc++) {
		எனில் (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			எனில் (cc->isctype((unsigned எழுத்து)test))
				rval = RANGE_MATCH;
			நிறுத்து;
		}
	}
	எனில் (cc->name == வெற்று) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	திரும்பு rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
நிலையான முழு fnmatch_ch(மாறிலி எழுத்து **pattern, மாறிலி எழுத்து **string, முழு flags)
{
	மாறிலி எழுத்து * மாறிலி mismatch = *pattern;
	மாறிலி முழு nocase = !!(flags & FNM_CASEFOLD);
	மாறிலி முழு escape = !(flags & FNM_NOESCAPE);
	மாறிலி முழு slash = !!(flags & FNM_PATHNAME);
	முழு result = FNM_NOMATCH;
	மாறிலி எழுத்து *startch;
	முழு negate;

	எனில் (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		எனில் (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		எனில் (**pattern == ']')
			செல் leadingclosebrace;

		போது (**pattern) {
			எனில் (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				திரும்பு (result ^ negate);
			}

			எனில் (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				எனில் (!**pattern)
					நிறுத்து;
			}

			/* Patterns must terminate with ']' not '/' */
			எனில் (slash && (**pattern == '/'))
				நிறுத்து;

			/* Match character classes. */
			தேர்வு (classmatch(*pattern, **string, nocase, pattern)) {
			நிலை RANGE_MATCH:
				result = 0;
				தொடர்;
			நிலை RANGE_NOMATCH:
				/* Valid character class but no match. */
				தொடர்;
			இயல்பு:
				/* Not a valid character class. */
				நிறுத்து;
			}
			எனில் (!**pattern)
				நிறுத்து;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			எனில் (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				எனில் (!**pattern || (slash && (**pattern == '/')))
					நிறுத்து;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				எனில் ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				இல்லையெனில் எனில் (nocase &&
				    (isupper((unsigned எழுத்து)**string) ||
				     isupper((unsigned எழுத்து)*startch) ||
				     isupper((unsigned எழுத்து)**pattern)) &&
				    (tolower((unsigned எழுத்து)**string) >=
				     tolower((unsigned எழுத்து)*startch)) &&
				    (tolower((unsigned எழுத்து)**string) <=
				     tolower((unsigned எழுத்து)**pattern)))
					result = 0;

				++*pattern;
				தொடர்;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			எனில் ((**string == **pattern))
				result = 0;
			இல்லையெனில் எனில் (nocase && (isupper((unsigned எழுத்து)**string) ||
			    isupper((unsigned எழுத்து)**pattern)) &&
			    (tolower((unsigned எழுத்து)**string) ==
			    tolower((unsigned எழுத்து)**pattern)))
				result = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		result = FNM_NOMATCH;
	} இல்லையெனில் எனில் (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		எனில் (!**string || (slash && (**string == '/')))
			திரும்பு FNM_NOMATCH;
		result = 0;
		செல் fnmatch_ch_success;
	} இல்லையெனில் எனில் (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	எனில் (**string == **pattern)
		result = 0;
	இல்லையெனில் எனில் (nocase && (isupper((unsigned எழுத்து)**string) ||
	    isupper((unsigned எழுத்து)**pattern)) &&
	    (tolower((unsigned எழுத்து)**string) ==
	    tolower((unsigned எழுத்து)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	எனில் (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		திரும்பு result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	திரும்பு result;
}


முழு fnmatch(மாறிலி எழுத்து *pattern, மாறிலி எழுத்து *string, முழு flags)
{
	நிலையான மாறிலி எழுத்து dummystring[2] = {' ', 0};
	மாறிலி முழு escape = !(flags & FNM_NOESCAPE);
	மாறிலி முழு slash = !!(flags & FNM_PATHNAME);
	மாறிலி முழு leading_dir = !!(flags & FNM_LEADING_DIR);
	மாறிலி எழுத்து *dummyptr, *matchptr, *strendseg;
	முழு wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	மாறிலி எழுத்து *strstartseg = வெற்று;
	மாறிலி எழுத்து *mismatch = வெற்று;
	முழு matchlen = 0;

	எனில் (*pattern == '*')
		செல் firstsegment;

	போது (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		எனில் (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		எனில் (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		எனில் ((flags & FNM_PERIOD) && (*string == '.')) {
		    எனில் (*pattern == '.')
			    ++pattern;
		    இல்லையெனில் எனில் (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    இல்லையெனில்
			    திரும்பு FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		எனில் (slash) {
			strendseg = strchr(string, '/');
			எனில் (!strendseg)
				strendseg = strchr(string, '\0');
		} இல்லையெனில் {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		போது (*pattern) {
			எனில் ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				நிறுத்து;

			எனில் (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				நிறுத்து;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			க்கு (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				எனில் (*pattern == '*') {
					wild = 1;
				} இல்லையெனில் எனில் (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				இல்லையெனில் {  /* (string >= strendseg) && (*pattern == '?') */
					திரும்பு FNM_NOMATCH;
				}
			}

			எனில் (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				க்கு (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					எனில் ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						எனில் (string + matchlen > strendseg)
							திரும்பு FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						நிறுத்து;
					}

					எனில் (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						எனில் (string + matchlen > strendseg)
							திரும்பு FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						நிறுத்து;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					எனில் (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} இல்லையெனில் எனில் (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} இல்லையெனில் {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			போது (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				எனில் (*pattern == '*')
					நிறுத்து;

				எனில் (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					நிறுத்து;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				எனில் (!fnmatch_ch(&pattern, &string, flags))
					தொடர்;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				எனில் (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					எனில் (string + matchlen > strendseg)
						திரும்பு FNM_NOMATCH;

					pattern = mismatch;
					தொடர்;
				} இல்லையெனில்
					திரும்பு FNM_NOMATCH;
			}
		}

		எனில் (*string && !((slash || leading_dir) && (*string == '/')))
			திரும்பு FNM_NOMATCH;

		எனில் (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			திரும்பு FNM_NOMATCH;

		எனில் (leading_dir && !*pattern && *string == '/')
			திரும்பு 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	எனில் (!*string && !*pattern)
		திரும்பு 0;

	/* Pattern didn't match to the end of string. */
	திரும்பு FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
