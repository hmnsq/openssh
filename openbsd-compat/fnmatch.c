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

static целое
classmatch(const char *pattern, char test, целое foldcase, const char **ep)
{
	const char * const mismatch = pattern;
	const char *colon;
	struct cclass *cc;
	целое rval = RANGE_NOMATCH;
	size_t len;

	если (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		вернуть RANGE_ERROR;
	}
	pattern += 2;

	если ((colon = strchr(pattern, ':')) == NULL || colon[1] != ']') {
		*ep = mismatch;
		вернуть RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	если (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	для (cc = cclasses; cc->name != NULL; cc++) {
		если (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			если (cc->isctype((unsigned char)test))
				rval = RANGE_MATCH;
			break;
		}
	}
	если (cc->name == NULL) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	вернуть rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
static целое fnmatch_ch(const char **pattern, const char **string, целое flags)
{
	const char * const mismatch = *pattern;
	const целое nocase = !!(flags & FNM_CASEFOLD);
	const целое escape = !(flags & FNM_NOESCAPE);
	const целое slash = !!(flags & FNM_PATHNAME);
	целое result = FNM_NOMATCH;
	const char *startch;
	целое negate;

	если (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		если (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		если (**pattern == ']')
			goto leadingclosebrace;

		пока (**pattern) {
			если (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				вернуть (result ^ negate);
			}

			если (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				если (!**pattern)
					break;
			}

			/* Patterns must terminate with ']' not '/' */
			если (slash && (**pattern == '/'))
				break;

			/* Match character classes. */
			switch (classmatch(*pattern, **string, nocase, pattern)) {
			case RANGE_MATCH:
				result = 0;
				continue;
			case RANGE_NOMATCH:
				/* Valid character class but no match. */
				continue;
			default:
				/* Not a valid character class. */
				break;
			}
			если (!**pattern)
				break;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			если (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				если (!**pattern || (slash && (**pattern == '/')))
					break;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				если ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				иначе если (nocase &&
				    (isupper((unsigned char)**string) ||
				     isupper((unsigned char)*startch) ||
				     isupper((unsigned char)**pattern)) &&
				    (tolower((unsigned char)**string) >=
				     tolower((unsigned char)*startch)) &&
				    (tolower((unsigned char)**string) <=
				     tolower((unsigned char)**pattern)))
					result = 0;

				++*pattern;
				continue;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			если ((**string == **pattern))
				result = 0;
			иначе если (nocase && (isupper((unsigned char)**string) ||
			    isupper((unsigned char)**pattern)) &&
			    (tolower((unsigned char)**string) ==
			    tolower((unsigned char)**pattern)))
				result = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		result = FNM_NOMATCH;
	} иначе если (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		если (!**string || (slash && (**string == '/')))
			вернуть FNM_NOMATCH;
		result = 0;
		goto fnmatch_ch_success;
	} иначе если (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	если (**string == **pattern)
		result = 0;
	иначе если (nocase && (isupper((unsigned char)**string) ||
	    isupper((unsigned char)**pattern)) &&
	    (tolower((unsigned char)**string) ==
	    tolower((unsigned char)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	если (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		вернуть result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	вернуть result;
}


целое fnmatch(const char *pattern, const char *string, целое flags)
{
	static const char dummystring[2] = {' ', 0};
	const целое escape = !(flags & FNM_NOESCAPE);
	const целое slash = !!(flags & FNM_PATHNAME);
	const целое leading_dir = !!(flags & FNM_LEADING_DIR);
	const char *dummyptr, *matchptr, *strendseg;
	целое wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	const char *strstartseg = NULL;
	const char *mismatch = NULL;
	целое matchlen = 0;

	если (*pattern == '*')
		goto firstsegment;

	пока (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		если (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		если (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		если ((flags & FNM_PERIOD) && (*string == '.')) {
		    если (*pattern == '.')
			    ++pattern;
		    иначе если (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    иначе
			    вернуть FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		если (slash) {
			strendseg = strchr(string, '/');
			если (!strendseg)
				strendseg = strchr(string, '\0');
		} иначе {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		пока (*pattern) {
			если ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				break;

			если (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				break;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			для (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				если (*pattern == '*') {
					wild = 1;
				} иначе если (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				иначе {  /* (string >= strendseg) && (*pattern == '?') */
					вернуть FNM_NOMATCH;
				}
			}

			если (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				для (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					если ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						если (string + matchlen > strendseg)
							вернуть FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						break;
					}

					если (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						если (string + matchlen > strendseg)
							вернуть FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						break;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					если (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} иначе если (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} иначе {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			пока (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				если (*pattern == '*')
					break;

				если (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					break;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				если (!fnmatch_ch(&pattern, &string, flags))
					continue;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				если (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					если (string + matchlen > strendseg)
						вернуть FNM_NOMATCH;

					pattern = mismatch;
					continue;
				} иначе
					вернуть FNM_NOMATCH;
			}
		}

		если (*string && !((slash || leading_dir) && (*string == '/')))
			вернуть FNM_NOMATCH;

		если (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			вернуть FNM_NOMATCH;

		если (leading_dir && !*pattern && *string == '/')
			вернуть 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	если (!*string && !*pattern)
		вернуть 0;

	/* Pattern didn't match to the end of string. */
	вернуть FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
