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

স্থির পূর্ণসংখ্যা
classmatch(ধ্রুবক অক্ষর *pattern, অক্ষর test, পূর্ণসংখ্যা foldcase, ধ্রুবক অক্ষর **ep)
{
	ধ্রুবক অক্ষর * ধ্রুবক mismatch = pattern;
	ধ্রুবক অক্ষর *colon;
	কাঠামো cclass *cc;
	পূর্ণসংখ্যা rval = RANGE_NOMATCH;
	আকার_t len;

	যদি (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		ফেরত RANGE_ERROR;
	}
	pattern += 2;

	যদি ((colon = strchr(pattern, ':')) == ফাঁকা || colon[1] != ']') {
		*ep = mismatch;
		ফেরত RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (আকার_t)(colon - pattern);

	যদি (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	জন্য (cc = cclasses; cc->name != ফাঁকা; cc++) {
		যদি (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			যদি (cc->isctype((unsigned অক্ষর)test))
				rval = RANGE_MATCH;
			বিরতি;
		}
	}
	যদি (cc->name == ফাঁকা) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	ফেরত rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
স্থির পূর্ণসংখ্যা fnmatch_ch(ধ্রুবক অক্ষর **pattern, ধ্রুবক অক্ষর **string, পূর্ণসংখ্যা flags)
{
	ধ্রুবক অক্ষর * ধ্রুবক mismatch = *pattern;
	ধ্রুবক পূর্ণসংখ্যা nocase = !!(flags & FNM_CASEFOLD);
	ধ্রুবক পূর্ণসংখ্যা escape = !(flags & FNM_NOESCAPE);
	ধ্রুবক পূর্ণসংখ্যা slash = !!(flags & FNM_PATHNAME);
	পূর্ণসংখ্যা ফলাফল = FNM_NOMATCH;
	ধ্রুবক অক্ষর *startch;
	পূর্ণসংখ্যা negate;

	যদি (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		যদি (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		যদি (**pattern == ']')
			যাও leadingclosebrace;

		যখন (**pattern) {
			যদি (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				ফেরত (ফলাফল ^ negate);
			}

			যদি (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				যদি (!**pattern)
					বিরতি;
			}

			/* Patterns must terminate with ']' not '/' */
			যদি (slash && (**pattern == '/'))
				বিরতি;

			/* Match character classes. */
			নির্বাচন (classmatch(*pattern, **string, nocase, pattern)) {
			ক্ষেত্র RANGE_MATCH:
				ফলাফল = 0;
				চালু;
			ক্ষেত্র RANGE_NOMATCH:
				/* Valid character class but no match. */
				চালু;
			পূর্বনির্ধারিত:
				/* Not a valid character class. */
				বিরতি;
			}
			যদি (!**pattern)
				বিরতি;

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
					বিরতি;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				যদি ((**string >= *startch) && (**string <= **pattern))
					ফলাফল = 0;
				অন্যথা যদি (nocase &&
				    (isupper((unsigned অক্ষর)**string) ||
				     isupper((unsigned অক্ষর)*startch) ||
				     isupper((unsigned অক্ষর)**pattern)) &&
				    (tolower((unsigned অক্ষর)**string) >=
				     tolower((unsigned অক্ষর)*startch)) &&
				    (tolower((unsigned অক্ষর)**string) <=
				     tolower((unsigned অক্ষর)**pattern)))
					ফলাফল = 0;

				++*pattern;
				চালু;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			যদি ((**string == **pattern))
				ফলাফল = 0;
			অন্যথা যদি (nocase && (isupper((unsigned অক্ষর)**string) ||
			    isupper((unsigned অক্ষর)**pattern)) &&
			    (tolower((unsigned অক্ষর)**string) ==
			    tolower((unsigned অক্ষর)**pattern)))
				ফলাফল = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		ফলাফল = FNM_NOMATCH;
	} অন্যথা যদি (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		যদি (!**string || (slash && (**string == '/')))
			ফেরত FNM_NOMATCH;
		ফলাফল = 0;
		যাও fnmatch_ch_success;
	} অন্যথা যদি (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	যদি (**string == **pattern)
		ফলাফল = 0;
	অন্যথা যদি (nocase && (isupper((unsigned অক্ষর)**string) ||
	    isupper((unsigned অক্ষর)**pattern)) &&
	    (tolower((unsigned অক্ষর)**string) ==
	    tolower((unsigned অক্ষর)**pattern)))
		ফলাফল = 0;

	/* Refuse to advance over trailing slash or NULs */
	যদি (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		ফেরত ফলাফল;

fnmatch_ch_success:
	++*pattern;
	++*string;
	ফেরত ফলাফল;
}


পূর্ণসংখ্যা fnmatch(ধ্রুবক অক্ষর *pattern, ধ্রুবক অক্ষর *string, পূর্ণসংখ্যা flags)
{
	স্থির ধ্রুবক অক্ষর dummystring[2] = {' ', 0};
	ধ্রুবক পূর্ণসংখ্যা escape = !(flags & FNM_NOESCAPE);
	ধ্রুবক পূর্ণসংখ্যা slash = !!(flags & FNM_PATHNAME);
	ধ্রুবক পূর্ণসংখ্যা leading_dir = !!(flags & FNM_LEADING_DIR);
	ধ্রুবক অক্ষর *dummyptr, *matchptr, *strendseg;
	পূর্ণসংখ্যা wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	ধ্রুবক অক্ষর *strstartseg = ফাঁকা;
	ধ্রুবক অক্ষর *mismatch = ফাঁকা;
	পূর্ণসংখ্যা matchlen = 0;

	যদি (*pattern == '*')
		যাও firstsegment;

	যখন (*pattern && *string) {
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
			    ফেরত FNM_NOMATCH;
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
		যখন (*pattern) {
			যদি ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				বিরতি;

			যদি (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				বিরতি;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			জন্য (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				যদি (*pattern == '*') {
					wild = 1;
				} অন্যথা যদি (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				অন্যথা {  /* (string >= strendseg) && (*pattern == '?') */
					ফেরত FNM_NOMATCH;
				}
			}

			যদি (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				জন্য (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
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
							ফেরত FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						বিরতি;
					}

					যদি (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						যদি (string + matchlen > strendseg)
							ফেরত FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						বিরতি;
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
			যখন (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				যদি (*pattern == '*')
					বিরতি;

				যদি (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					বিরতি;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				যদি (!fnmatch_ch(&pattern, &string, flags))
					চালু;

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
						ফেরত FNM_NOMATCH;

					pattern = mismatch;
					চালু;
				} অন্যথা
					ফেরত FNM_NOMATCH;
			}
		}

		যদি (*string && !((slash || leading_dir) && (*string == '/')))
			ফেরত FNM_NOMATCH;

		যদি (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			ফেরত FNM_NOMATCH;

		যদি (leading_dir && !*pattern && *string == '/')
			ফেরত 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	যদি (!*string && !*pattern)
		ফেরত 0;

	/* Pattern didn't match to the end of string. */
	ফেরত FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
