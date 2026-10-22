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

#ضمن "includes.h"
#ifndef HAVE_FNMATCH

#ضمن <fnmatch.h>
#ضمن <string.h>
#ضمن <ctype.h>

#ضمن "charclass.h"

#define	RANGE_MATCH	1
#define	RANGE_NOMATCH	0
#define	RANGE_ERROR	(-1)

ساكن صحيح
classmatch(ثابت حرف *pattern, حرف test, صحيح foldcase, ثابت حرف **ep)
{
	ثابت حرف * ثابت mismatch = pattern;
	ثابت حرف *colon;
	بنية cclass *cc;
	صحيح rval = RANGE_NOMATCH;
	size_t len;

	אם (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		החזר RANGE_ERROR;
	}
	pattern += 2;

	אם ((colon = strchr(pattern, ':')) == عدم || colon[1] != ']') {
		*ep = mismatch;
		החזר RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	אם (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	עבור (cc = cclasses; cc->name != عدم; cc++) {
		אם (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			אם (cc->isctype((unsigned حرف)test))
				rval = RANGE_MATCH;
			اكسر;
		}
	}
	אם (cc->name == عدم) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	החזר rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
ساكن صحيح fnmatch_ch(ثابت حرف **pattern, ثابت حرف **string, صحيح flags)
{
	ثابت حرف * ثابت mismatch = *pattern;
	ثابت صحيح nocase = !!(flags & FNM_CASEFOLD);
	ثابت صحيح escape = !(flags & FNM_NOESCAPE);
	ثابت صحيح slash = !!(flags & FNM_PATHNAME);
	صحيح result = FNM_NOMATCH;
	ثابت حرف *startch;
	صحيح negate;

	אם (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		אם (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		אם (**pattern == ']')
			اذهب leadingclosebrace;

		כלעוד (**pattern) {
			אם (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				החזר (result ^ negate);
			}

			אם (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				אם (!**pattern)
					اكسر;
			}

			/* Patterns must terminate with ']' not '/' */
			אם (slash && (**pattern == '/'))
				اكسر;

			/* Match character classes. */
			بدل (classmatch(*pattern, **string, nocase, pattern)) {
			حالة RANGE_MATCH:
				result = 0;
				استمر;
			حالة RANGE_NOMATCH:
				/* Valid character class but no match. */
				استمر;
			افتراضي:
				/* Not a valid character class. */
				اكسر;
			}
			אם (!**pattern)
				اكسر;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			אם (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				אם (!**pattern || (slash && (**pattern == '/')))
					اكسر;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				אם ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				אחרת אם (nocase &&
				    (isupper((unsigned حرف)**string) ||
				     isupper((unsigned حرف)*startch) ||
				     isupper((unsigned حرف)**pattern)) &&
				    (tolower((unsigned حرف)**string) >=
				     tolower((unsigned حرف)*startch)) &&
				    (tolower((unsigned حرف)**string) <=
				     tolower((unsigned حرف)**pattern)))
					result = 0;

				++*pattern;
				استمر;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			אם ((**string == **pattern))
				result = 0;
			אחרת אם (nocase && (isupper((unsigned حرف)**string) ||
			    isupper((unsigned حرف)**pattern)) &&
			    (tolower((unsigned حرف)**string) ==
			    tolower((unsigned حرف)**pattern)))
				result = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		result = FNM_NOMATCH;
	} אחרת אם (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		אם (!**string || (slash && (**string == '/')))
			החזר FNM_NOMATCH;
		result = 0;
		اذهب fnmatch_ch_success;
	} אחרת אם (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	אם (**string == **pattern)
		result = 0;
	אחרת אם (nocase && (isupper((unsigned حرف)**string) ||
	    isupper((unsigned حرف)**pattern)) &&
	    (tolower((unsigned حرف)**string) ==
	    tolower((unsigned حرف)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	אם (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		החזר result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	החזר result;
}


صحيح fnmatch(ثابت حرف *pattern, ثابت حرف *string, صحيح flags)
{
	ساكن ثابت حرف dummystring[2] = {' ', 0};
	ثابت صحيح escape = !(flags & FNM_NOESCAPE);
	ثابت صحيح slash = !!(flags & FNM_PATHNAME);
	ثابت صحيح leading_dir = !!(flags & FNM_LEADING_DIR);
	ثابت حرف *dummyptr, *matchptr, *strendseg;
	صحيح wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	ثابت حرف *strstartseg = عدم;
	ثابت حرف *mismatch = عدم;
	صحيح matchlen = 0;

	אם (*pattern == '*')
		اذهب firstsegment;

	כלעוד (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		אם (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		אם (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		אם ((flags & FNM_PERIOD) && (*string == '.')) {
		    אם (*pattern == '.')
			    ++pattern;
		    אחרת אם (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    אחרת
			    החזר FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		אם (slash) {
			strendseg = strchr(string, '/');
			אם (!strendseg)
				strendseg = strchr(string, '\0');
		} אחרת {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		כלעוד (*pattern) {
			אם ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				اكسر;

			אם (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				اكسر;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			עבור (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				אם (*pattern == '*') {
					wild = 1;
				} אחרת אם (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				אחרת {  /* (string >= strendseg) && (*pattern == '?') */
					החזר FNM_NOMATCH;
				}
			}

			אם (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				עבור (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					אם ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						אם (string + matchlen > strendseg)
							החזר FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						اكسر;
					}

					אם (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						אם (string + matchlen > strendseg)
							החזר FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						اكسر;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					אם (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} אחרת אם (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} אחרת {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			כלעוד (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				אם (*pattern == '*')
					اكسر;

				אם (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					اكسر;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				אם (!fnmatch_ch(&pattern, &string, flags))
					استمر;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				אם (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					אם (string + matchlen > strendseg)
						החזר FNM_NOMATCH;

					pattern = mismatch;
					استمر;
				} אחרת
					החזר FNM_NOMATCH;
			}
		}

		אם (*string && !((slash || leading_dir) && (*string == '/')))
			החזר FNM_NOMATCH;

		אם (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			החזר FNM_NOMATCH;

		אם (leading_dir && !*pattern && *string == '/')
			החזר 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	אם (!*string && !*pattern)
		החזר 0;

	/* Pattern didn't match to the end of string. */
	החזר FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
