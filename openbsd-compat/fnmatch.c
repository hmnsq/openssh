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

#অন্তর্ভাব "includes.h"
#ifndef HAVE_FNMATCH

#অন্তর্ভাব <fnmatch.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <ctype.h>

#অন্তর্ভাব "charclass.h"

#define	RANGE_MATCH	1
#define	RANGE_NOMATCH	0
#define	RANGE_ERROR	(-1)

স্থির পূর্ণাঙ্ক
classmatch(ধ্রুব বর্ণ *pattern, বর্ণ test, পূর্ণাঙ্ক foldcase, ধ্রুব বর্ণ **ep)
{
	ধ্রুব বর্ণ * ধ্রুব mismatch = pattern;
	ধ্রুব বর্ণ *colon;
	সংরচনা cclass *cc;
	পূর্ণাঙ্ক rval = RANGE_NOMATCH;
	size_t len;

	যদি (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		প্রত্যাগম RANGE_ERROR;
	}
	pattern += 2;

	যদি ((colon = strchr(pattern, ':')) == রিক্ত || colon[1] != ']') {
		*ep = mismatch;
		প্রত্যাগম RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	যদি (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	প্রতি (cc = cclasses; cc->name != রিক্ত; cc++) {
		যদি (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			যদি (cc->isctype((unsigned বর্ণ)test))
				rval = RANGE_MATCH;
			ভঙ্গ;
		}
	}
	যদি (cc->name == রিক্ত) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	প্রত্যাগম rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
স্থির পূর্ণাঙ্ক fnmatch_ch(ধ্রুব বর্ণ **pattern, ধ্রুব বর্ণ **string, পূর্ণাঙ্ক flags)
{
	ধ্রুব বর্ণ * ধ্রুব mismatch = *pattern;
	ধ্রুব পূর্ণাঙ্ক nocase = !!(flags & FNM_CASEFOLD);
	ধ্রুব পূর্ণাঙ্ক escape = !(flags & FNM_NOESCAPE);
	ধ্রুব পূর্ণাঙ্ক slash = !!(flags & FNM_PATHNAME);
	পূর্ণাঙ্ক result = FNM_NOMATCH;
	ধ্রুব বর্ণ *startch;
	পূর্ণাঙ্ক negate;

	যদি (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		যদি (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		যদি (**pattern == ']')
			গচ্ছ leadingclosebrace;

		যাবত্ (**pattern) {
			যদি (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				প্রত্যাগম (result ^ negate);
			}

			যদি (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				যদি (!**pattern)
					ভঙ্গ;
			}

			/* Patterns must terminate with ']' not '/' */
			যদি (slash && (**pattern == '/'))
				ভঙ্গ;

			/* Match character classes. */
			বিকল্প (classmatch(*pattern, **string, nocase, pattern)) {
			পক্ষ RANGE_MATCH:
				result = 0;
				অনুবর্ত;
			পক্ষ RANGE_NOMATCH:
				/* Valid character class but no match. */
				অনুবর্ত;
			স্বভাব:
				/* Not a valid character class. */
				ভঙ্গ;
			}
			যদি (!**pattern)
				ভঙ্গ;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			যদি (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				যদি (!**pattern || (slash && (**pattern == '/')))
					ভঙ্গ;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				যদি ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				অন্যথা যদি (nocase &&
				    (isupper((unsigned বর্ণ)**string) ||
				     isupper((unsigned বর্ণ)*startch) ||
				     isupper((unsigned বর্ণ)**pattern)) &&
				    (tolower((unsigned বর্ণ)**string) >=
				     tolower((unsigned বর্ণ)*startch)) &&
				    (tolower((unsigned বর্ণ)**string) <=
				     tolower((unsigned বর্ণ)**pattern)))
					result = 0;

				++*pattern;
				অনুবর্ত;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			যদি ((**string == **pattern))
				result = 0;
			অন্যথা যদি (nocase && (isupper((unsigned বর্ণ)**string) ||
			    isupper((unsigned বর্ণ)**pattern)) &&
			    (tolower((unsigned বর্ণ)**string) ==
			    tolower((unsigned বর্ণ)**pattern)))
				result = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		result = FNM_NOMATCH;
	} অন্যথা যদি (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		যদি (!**string || (slash && (**string == '/')))
			প্রত্যাগম FNM_NOMATCH;
		result = 0;
		গচ্ছ fnmatch_ch_success;
	} অন্যথা যদি (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	যদি (**string == **pattern)
		result = 0;
	অন্যথা যদি (nocase && (isupper((unsigned বর্ণ)**string) ||
	    isupper((unsigned বর্ণ)**pattern)) &&
	    (tolower((unsigned বর্ণ)**string) ==
	    tolower((unsigned বর্ণ)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	যদি (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		প্রত্যাগম result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	প্রত্যাগম result;
}


পূর্ণাঙ্ক fnmatch(ধ্রুব বর্ণ *pattern, ধ্রুব বর্ণ *string, পূর্ণাঙ্ক flags)
{
	স্থির ধ্রুব বর্ণ dummystring[2] = {' ', 0};
	ধ্রুব পূর্ণাঙ্ক escape = !(flags & FNM_NOESCAPE);
	ধ্রুব পূর্ণাঙ্ক slash = !!(flags & FNM_PATHNAME);
	ধ্রুব পূর্ণাঙ্ক leading_dir = !!(flags & FNM_LEADING_DIR);
	ধ্রুব বর্ণ *dummyptr, *matchptr, *strendseg;
	পূর্ণাঙ্ক wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	ধ্রুব বর্ণ *strstartseg = রিক্ত;
	ধ্রুব বর্ণ *mismatch = রিক্ত;
	পূর্ণাঙ্ক matchlen = 0;

	যদি (*pattern == '*')
		গচ্ছ firstsegment;

	যাবত্ (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		যদি (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		যদি (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		যদি ((flags & FNM_PERIOD) && (*string == '.')) {
		    যদি (*pattern == '.')
			    ++pattern;
		    অন্যথা যদি (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    অন্যথা
			    প্রত্যাগম FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		যদি (slash) {
			strendseg = strchr(string, '/');
			যদি (!strendseg)
				strendseg = strchr(string, '\0');
		} অন্যথা {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		যাবত্ (*pattern) {
			যদি ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				ভঙ্গ;

			যদি (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				ভঙ্গ;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			প্রতি (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				যদি (*pattern == '*') {
					wild = 1;
				} অন্যথা যদি (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				অন্যথা {  /* (string >= strendseg) && (*pattern == '?') */
					প্রত্যাগম FNM_NOMATCH;
				}
			}

			যদি (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				প্রতি (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					যদি ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						যদি (string + matchlen > strendseg)
							প্রত্যাগম FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						ভঙ্গ;
					}

					যদি (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						যদি (string + matchlen > strendseg)
							প্রত্যাগম FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						ভঙ্গ;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					যদি (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} অন্যথা যদি (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} অন্যথা {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			যাবত্ (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				যদি (*pattern == '*')
					ভঙ্গ;

				যদি (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					ভঙ্গ;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				যদি (!fnmatch_ch(&pattern, &string, flags))
					অনুবর্ত;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				যদি (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					যদি (string + matchlen > strendseg)
						প্রত্যাগম FNM_NOMATCH;

					pattern = mismatch;
					অনুবর্ত;
				} অন্যথা
					প্রত্যাগম FNM_NOMATCH;
			}
		}

		যদি (*string && !((slash || leading_dir) && (*string == '/')))
			প্রত্যাগম FNM_NOMATCH;

		যদি (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			প্রত্যাগম FNM_NOMATCH;

		যদি (leading_dir && !*pattern && *string == '/')
			প্রত্যাগম 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	যদি (!*string && !*pattern)
		প্রত্যাগম 0;

	/* Pattern didn't match to the end of string. */
	প্রত্যাগম FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
