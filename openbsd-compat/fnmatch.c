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

static ចំនួនគត់
classmatch(const var_na *pattern, var_na test, ចំនួនគត់ foldcase, const var_na **ep)
{
	const var_na * const mismatch = pattern;
	const var_na *colon;
	sa_nracanaa cclass *cc;
	ចំនួនគត់ rval = RANGE_NOMATCH;
	size_t len;

	ប្រសិនបើ (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		ត្រឡប់ RANGE_ERROR;
	}
	pattern += 2;

	ប្រសិនបើ ((colon = strchr(pattern, ':')) == NULL || colon[1] != ']') {
		*ep = mismatch;
		ត្រឡប់ RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	ប្រសិនបើ (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	សម្រាប់ (cc = cclasses; cc->name != NULL; cc++) {
		ប្រសិនបើ (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			ប្រសិនបើ (cc->isctype((unsigned var_na)test))
				rval = RANGE_MATCH;
			bha_nga;
		}
	}
	ប្រសិនបើ (cc->name == NULL) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	ត្រឡប់ rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
static ចំនួនគត់ fnmatch_ch(const var_na **pattern, const var_na **string, ចំនួនគត់ flags)
{
	const var_na * const mismatch = *pattern;
	const ចំនួនគត់ nocase = !!(flags & FNM_CASEFOLD);
	const ចំនួនគត់ escape = !(flags & FNM_NOESCAPE);
	const ចំនួនគត់ slash = !!(flags & FNM_PATHNAME);
	ចំនួនគត់ result = FNM_NOMATCH;
	const var_na *startch;
	ចំនួនគត់ negate;

	ប្រសិនបើ (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		ប្រសិនបើ (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		ប្រសិនបើ (**pattern == ']')
			goto leadingclosebrace;

		ខណៈពេល (**pattern) {
			ប្រសិនបើ (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				ត្រឡប់ (result ^ negate);
			}

			ប្រសិនបើ (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				ប្រសិនបើ (!**pattern)
					bha_nga;
			}

			/* Patterns must terminate with ']' not '/' */
			ប្រសិនបើ (slash && (**pattern == '/'))
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
			ប្រសិនបើ (!**pattern)
				bha_nga;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			ប្រសិនបើ (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				ប្រសិនបើ (!**pattern || (slash && (**pattern == '/')))
					bha_nga;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				ប្រសិនបើ ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				បើមិនដូច្នេះ ប្រសិនបើ (nocase &&
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
			ប្រសិនបើ ((**string == **pattern))
				result = 0;
			បើមិនដូច្នេះ ប្រសិនបើ (nocase && (isupper((unsigned var_na)**string) ||
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
	} បើមិនដូច្នេះ ប្រសិនបើ (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		ប្រសិនបើ (!**string || (slash && (**string == '/')))
			ត្រឡប់ FNM_NOMATCH;
		result = 0;
		goto fnmatch_ch_success;
	} បើមិនដូច្នេះ ប្រសិនបើ (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	ប្រសិនបើ (**string == **pattern)
		result = 0;
	បើមិនដូច្នេះ ប្រសិនបើ (nocase && (isupper((unsigned var_na)**string) ||
	    isupper((unsigned var_na)**pattern)) &&
	    (tolower((unsigned var_na)**string) ==
	    tolower((unsigned var_na)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	ប្រសិនបើ (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		ត្រឡប់ result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	ត្រឡប់ result;
}


ចំនួនគត់ fnmatch(const var_na *pattern, const var_na *string, ចំនួនគត់ flags)
{
	static const var_na dummystring[2] = {' ', 0};
	const ចំនួនគត់ escape = !(flags & FNM_NOESCAPE);
	const ចំនួនគត់ slash = !!(flags & FNM_PATHNAME);
	const ចំនួនគត់ leading_dir = !!(flags & FNM_LEADING_DIR);
	const var_na *dummyptr, *matchptr, *strendseg;
	ចំនួនគត់ wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	const var_na *strstartseg = NULL;
	const var_na *mismatch = NULL;
	ចំនួនគត់ matchlen = 0;

	ប្រសិនបើ (*pattern == '*')
		goto firstsegment;

	ខណៈពេល (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		ប្រសិនបើ (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		ប្រសិនបើ (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		ប្រសិនបើ ((flags & FNM_PERIOD) && (*string == '.')) {
		    ប្រសិនបើ (*pattern == '.')
			    ++pattern;
		    បើមិនដូច្នេះ ប្រសិនបើ (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    បើមិនដូច្នេះ
			    ត្រឡប់ FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		ប្រសិនបើ (slash) {
			strendseg = strchr(string, '/');
			ប្រសិនបើ (!strendseg)
				strendseg = strchr(string, '\0');
		} បើមិនដូច្នេះ {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		ខណៈពេល (*pattern) {
			ប្រសិនបើ ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				bha_nga;

			ប្រសិនបើ (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				bha_nga;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			សម្រាប់ (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				ប្រសិនបើ (*pattern == '*') {
					wild = 1;
				} បើមិនដូច្នេះ ប្រសិនបើ (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				បើមិនដូច្នេះ {  /* (string >= strendseg) && (*pattern == '?') */
					ត្រឡប់ FNM_NOMATCH;
				}
			}

			ប្រសិនបើ (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				សម្រាប់ (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					ប្រសិនបើ ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						ប្រសិនបើ (string + matchlen > strendseg)
							ត្រឡប់ FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						bha_nga;
					}

					ប្រសិនបើ (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						ប្រសិនបើ (string + matchlen > strendseg)
							ត្រឡប់ FNM_NOMATCH;

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
					ប្រសិនបើ (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} បើមិនដូច្នេះ ប្រសិនបើ (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} បើមិនដូច្នេះ {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			ខណៈពេល (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				ប្រសិនបើ (*pattern == '*')
					bha_nga;

				ប្រសិនបើ (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					bha_nga;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				ប្រសិនបើ (!fnmatch_ch(&pattern, &string, flags))
					continue;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				ប្រសិនបើ (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					ប្រសិនបើ (string + matchlen > strendseg)
						ត្រឡប់ FNM_NOMATCH;

					pattern = mismatch;
					continue;
				} បើមិនដូច្នេះ
					ត្រឡប់ FNM_NOMATCH;
			}
		}

		ប្រសិនបើ (*string && !((slash || leading_dir) && (*string == '/')))
			ត្រឡប់ FNM_NOMATCH;

		ប្រសិនបើ (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			ត្រឡប់ FNM_NOMATCH;

		ប្រសិនបើ (leading_dir && !*pattern && *string == '/')
			ត្រឡប់ 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	ប្រសិនបើ (!*string && !*pattern)
		ត្រឡប់ 0;

	/* Pattern didn't match to the end of string. */
	ត្រឡប់ FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
