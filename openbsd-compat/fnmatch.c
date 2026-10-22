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

#شامل "includes.h"
#ifndef HAVE_FNMATCH

#شامل <fnmatch.h>
#شامل <string.h>
#شامل <ctype.h>

#شامل "charclass.h"

#define	RANGE_MATCH	1
#define	RANGE_NOMATCH	0
#define	RANGE_ERROR	(-1)

ایستا صحیح
classmatch(ثابت نویسه *pattern, نویسه test, صحیح foldcase, ثابت نویسه **ep)
{
	ثابت نویسه * ثابت mismatch = pattern;
	ثابت نویسه *colon;
	ساختار cclass *cc;
	صحیح rval = RANGE_NOMATCH;
	size_t len;

	اگر (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		بازگشت RANGE_ERROR;
	}
	pattern += 2;

	اگر ((colon = strchr(pattern, ':')) == پوچ || colon[1] != ']') {
		*ep = mismatch;
		بازگشت RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	اگر (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	برای (cc = cclasses; cc->name != پوچ; cc++) {
		اگر (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			اگر (cc->isctype((unsigned نویسه)test))
				rval = RANGE_MATCH;
			بشکن;
		}
	}
	اگر (cc->name == پوچ) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	بازگشت rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
ایستا صحیح fnmatch_ch(ثابت نویسه **pattern, ثابت نویسه **string, صحیح flags)
{
	ثابت نویسه * ثابت mismatch = *pattern;
	ثابت صحیح nocase = !!(flags & FNM_CASEFOLD);
	ثابت صحیح escape = !(flags & FNM_NOESCAPE);
	ثابت صحیح slash = !!(flags & FNM_PATHNAME);
	صحیح result = FNM_NOMATCH;
	ثابت نویسه *startch;
	صحیح negate;

	اگر (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		اگر (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		اگر (**pattern == ']')
			برو leadingclosebrace;

		وقتی (**pattern) {
			اگر (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				بازگشت (result ^ negate);
			}

			اگر (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				اگر (!**pattern)
					بشکن;
			}

			/* Patterns must terminate with ']' not '/' */
			اگر (slash && (**pattern == '/'))
				بشکن;

			/* Match character classes. */
			انتخاب (classmatch(*pattern, **string, nocase, pattern)) {
			حالت RANGE_MATCH:
				result = 0;
				ادامه;
			حالت RANGE_NOMATCH:
				/* Valid character class but no match. */
				ادامه;
			پیشفرض:
				/* Not a valid character class. */
				بشکن;
			}
			اگر (!**pattern)
				بشکن;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			اگر (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				اگر (!**pattern || (slash && (**pattern == '/')))
					بشکن;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				اگر ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				وگرنه اگر (nocase &&
				    (isupper((unsigned نویسه)**string) ||
				     isupper((unsigned نویسه)*startch) ||
				     isupper((unsigned نویسه)**pattern)) &&
				    (tolower((unsigned نویسه)**string) >=
				     tolower((unsigned نویسه)*startch)) &&
				    (tolower((unsigned نویسه)**string) <=
				     tolower((unsigned نویسه)**pattern)))
					result = 0;

				++*pattern;
				ادامه;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			اگر ((**string == **pattern))
				result = 0;
			وگرنه اگر (nocase && (isupper((unsigned نویسه)**string) ||
			    isupper((unsigned نویسه)**pattern)) &&
			    (tolower((unsigned نویسه)**string) ==
			    tolower((unsigned نویسه)**pattern)))
				result = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		result = FNM_NOMATCH;
	} وگرنه اگر (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		اگر (!**string || (slash && (**string == '/')))
			بازگشت FNM_NOMATCH;
		result = 0;
		برو fnmatch_ch_success;
	} وگرنه اگر (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	اگر (**string == **pattern)
		result = 0;
	وگرنه اگر (nocase && (isupper((unsigned نویسه)**string) ||
	    isupper((unsigned نویسه)**pattern)) &&
	    (tolower((unsigned نویسه)**string) ==
	    tolower((unsigned نویسه)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	اگر (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		بازگشت result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	بازگشت result;
}


صحیح fnmatch(ثابت نویسه *pattern, ثابت نویسه *string, صحیح flags)
{
	ایستا ثابت نویسه dummystring[2] = {' ', 0};
	ثابت صحیح escape = !(flags & FNM_NOESCAPE);
	ثابت صحیح slash = !!(flags & FNM_PATHNAME);
	ثابت صحیح leading_dir = !!(flags & FNM_LEADING_DIR);
	ثابت نویسه *dummyptr, *matchptr, *strendseg;
	صحیح wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	ثابت نویسه *strstartseg = پوچ;
	ثابت نویسه *mismatch = پوچ;
	صحیح matchlen = 0;

	اگر (*pattern == '*')
		برو firstsegment;

	وقتی (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		اگر (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		اگر (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		اگر ((flags & FNM_PERIOD) && (*string == '.')) {
		    اگر (*pattern == '.')
			    ++pattern;
		    وگرنه اگر (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    وگرنه
			    بازگشت FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		اگر (slash) {
			strendseg = strchr(string, '/');
			اگر (!strendseg)
				strendseg = strchr(string, '\0');
		} وگرنه {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		وقتی (*pattern) {
			اگر ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				بشکن;

			اگر (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				بشکن;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			برای (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				اگر (*pattern == '*') {
					wild = 1;
				} وگرنه اگر (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				وگرنه {  /* (string >= strendseg) && (*pattern == '?') */
					بازگشت FNM_NOMATCH;
				}
			}

			اگر (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				برای (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					اگر ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						اگر (string + matchlen > strendseg)
							بازگشت FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						بشکن;
					}

					اگر (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						اگر (string + matchlen > strendseg)
							بازگشت FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						بشکن;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					اگر (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} وگرنه اگر (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} وگرنه {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			وقتی (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				اگر (*pattern == '*')
					بشکن;

				اگر (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					بشکن;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				اگر (!fnmatch_ch(&pattern, &string, flags))
					ادامه;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				اگر (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					اگر (string + matchlen > strendseg)
						بازگشت FNM_NOMATCH;

					pattern = mismatch;
					ادامه;
				} وگرنه
					بازگشت FNM_NOMATCH;
			}
		}

		اگر (*string && !((slash || leading_dir) && (*string == '/')))
			بازگشت FNM_NOMATCH;

		اگر (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			بازگشت FNM_NOMATCH;

		اگر (leading_dir && !*pattern && *string == '/')
			بازگشت 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	اگر (!*string && !*pattern)
		بازگشت 0;

	/* Pattern didn't match to the end of string. */
	بازگشت FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
