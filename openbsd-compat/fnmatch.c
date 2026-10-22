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

#include "includes.h"
#ifndef HAVE_FNMATCH

#include <fnmatch.h>
#include <string.h>
#include <ctype.h>

#include "charclass.h"

#define	RANGE_MATCH	1
#define	RANGE_NOMATCH	0
#define	RANGE_ERROR	(-1)

static පූර්ණ_සංඛ්‍යා
classmatch(const var_na *pattern, var_na test, පූර්ණ_සංඛ්‍යා foldcase, const var_na **ep)
{
	const var_na * const mismatch = pattern;
	const var_na *colon;
	sa_nracanaa cclass *cc;
	පූර්ණ_සංඛ්‍යා rval = RANGE_NOMATCH;
	size_t len;

	නම් (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		ආපසු RANGE_ERROR;
	}
	pattern += 2;

	නම් ((colon = strchr(pattern, ':')) == NULL || colon[1] != ']') {
		*ep = mismatch;
		ආපසු RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	නම් (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	සඳහා (cc = cclasses; cc->name != NULL; cc++) {
		නම් (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			නම් (cc->isctype((unsigned var_na)test))
				rval = RANGE_MATCH;
			bha_nga;
		}
	}
	නම් (cc->name == NULL) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	ආපසු rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
static පූර්ණ_සංඛ්‍යා fnmatch_ch(const var_na **pattern, const var_na **string, පූර්ණ_සංඛ්‍යා flags)
{
	const var_na * const mismatch = *pattern;
	const පූර්ණ_සංඛ්‍යා nocase = !!(flags & FNM_CASEFOLD);
	const පූර්ණ_සංඛ්‍යා escape = !(flags & FNM_NOESCAPE);
	const පූර්ණ_සංඛ්‍යා slash = !!(flags & FNM_PATHNAME);
	පූර්ණ_සංඛ්‍යා result = FNM_NOMATCH;
	const var_na *startch;
	පූර්ණ_සංඛ්‍යා negate;

	නම් (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		නම් (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		නම් (**pattern == ']')
			goto leadingclosebrace;

		අතරතුර (**pattern) {
			නම් (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				ආපසු (result ^ negate);
			}

			නම් (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				නම් (!**pattern)
					bha_nga;
			}

			/* Patterns must terminate with ']' not '/' */
			නම් (slash && (**pattern == '/'))
				bha_nga;

			/* Match character classes. */
			switch (classmatch(*pattern, **string, nocase, pattern)) {
			pak_sa RANGE_MATCH:
				result = 0;
				continue;
			pak_sa RANGE_NOMATCH:
				/* Valid character class but no match. */
				continue;
			default:
				/* Not a valid character class. */
				bha_nga;
			}
			නම් (!**pattern)
				bha_nga;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			නම් (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				නම් (!**pattern || (slash && (**pattern == '/')))
					bha_nga;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				නම් ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				නැතහොත් නම් (nocase &&
				    (isupper((unsigned var_na)**string) ||
				     isupper((unsigned var_na)*startch) ||
				     isupper((unsigned var_na)**pattern)) &&
				    (tolower((unsigned var_na)**string) >=
				     tolower((unsigned var_na)*startch)) &&
				    (tolower((unsigned var_na)**string) <=
				     tolower((unsigned var_na)**pattern)))
					result = 0;

				++*pattern;
				continue;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			නම් ((**string == **pattern))
				result = 0;
			නැතහොත් නම් (nocase && (isupper((unsigned var_na)**string) ||
			    isupper((unsigned var_na)**pattern)) &&
			    (tolower((unsigned var_na)**string) ==
			    tolower((unsigned var_na)**pattern)))
				result = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		result = FNM_NOMATCH;
	} නැතහොත් නම් (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		නම් (!**string || (slash && (**string == '/')))
			ආපසු FNM_NOMATCH;
		result = 0;
		goto fnmatch_ch_success;
	} නැතහොත් නම් (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	නම් (**string == **pattern)
		result = 0;
	නැතහොත් නම් (nocase && (isupper((unsigned var_na)**string) ||
	    isupper((unsigned var_na)**pattern)) &&
	    (tolower((unsigned var_na)**string) ==
	    tolower((unsigned var_na)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	නම් (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		ආපසු result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	ආපසු result;
}


පූර්ණ_සංඛ්‍යා fnmatch(const var_na *pattern, const var_na *string, පූර්ණ_සංඛ්‍යා flags)
{
	static const var_na dummystring[2] = {' ', 0};
	const පූර්ණ_සංඛ්‍යා escape = !(flags & FNM_NOESCAPE);
	const පූර්ණ_සංඛ්‍යා slash = !!(flags & FNM_PATHNAME);
	const පූර්ණ_සංඛ්‍යා leading_dir = !!(flags & FNM_LEADING_DIR);
	const var_na *dummyptr, *matchptr, *strendseg;
	පූර්ණ_සංඛ්‍යා wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	const var_na *strstartseg = NULL;
	const var_na *mismatch = NULL;
	පූර්ණ_සංඛ්‍යා matchlen = 0;

	නම් (*pattern == '*')
		goto firstsegment;

	අතරතුර (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		නම් (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		නම් (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		නම් ((flags & FNM_PERIOD) && (*string == '.')) {
		    නම් (*pattern == '.')
			    ++pattern;
		    නැතහොත් නම් (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    නැතහොත්
			    ආපසු FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		නම් (slash) {
			strendseg = strchr(string, '/');
			නම් (!strendseg)
				strendseg = strchr(string, '\0');
		} නැතහොත් {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		අතරතුර (*pattern) {
			නම් ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				bha_nga;

			නම් (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				bha_nga;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			සඳහා (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				නම් (*pattern == '*') {
					wild = 1;
				} නැතහොත් නම් (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				නැතහොත් {  /* (string >= strendseg) && (*pattern == '?') */
					ආපසු FNM_NOMATCH;
				}
			}

			නම් (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				සඳහා (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					නම් ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						නම් (string + matchlen > strendseg)
							ආපසු FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						bha_nga;
					}

					නම් (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						නම් (string + matchlen > strendseg)
							ආපසු FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						bha_nga;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					නම් (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} නැතහොත් නම් (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} නැතහොත් {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			අතරතුර (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				නම් (*pattern == '*')
					bha_nga;

				නම් (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					bha_nga;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				නම් (!fnmatch_ch(&pattern, &string, flags))
					continue;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				නම් (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					නම් (string + matchlen > strendseg)
						ආපසු FNM_NOMATCH;

					pattern = mismatch;
					continue;
				} නැතහොත්
					ආපසු FNM_NOMATCH;
			}
		}

		නම් (*string && !((slash || leading_dir) && (*string == '/')))
			ආපසු FNM_NOMATCH;

		නම් (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			ආපසු FNM_NOMATCH;

		නම් (leading_dir && !*pattern && *string == '/')
			ආපසු 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	නම් (!*string && !*pattern)
		ආපසු 0;

	/* Pattern didn't match to the end of string. */
	ආපසු FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
