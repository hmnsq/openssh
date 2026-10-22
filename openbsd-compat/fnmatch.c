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

#અન્તર્ભાવ "includes.h"
#ifndef HAVE_FNMATCH

#અન્તર્ભાવ <fnmatch.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <ctype.h>

#અન્તર્ભાવ "charclass.h"

#define	RANGE_MATCH	1
#define	RANGE_NOMATCH	0
#define	RANGE_ERROR	(-1)

સ્થિર પૂર્ણાંક
classmatch(અચલ અક્ષર *pattern, અક્ષર test, પૂર્ણાંક foldcase, અચલ અક્ષર **ep)
{
	અચલ અક્ષર * અચલ mismatch = pattern;
	અચલ અક્ષર *colon;
	સંરચના cclass *cc;
	પૂર્ણાંક rval = RANGE_NOMATCH;
	size_t len;

	જો (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		પાછા RANGE_ERROR;
	}
	pattern += 2;

	જો ((colon = strchr(pattern, ':')) == ખાલી || colon[1] != ']') {
		*ep = mismatch;
		પાછા RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	જો (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	માટે (cc = cclasses; cc->name != ખાલી; cc++) {
		જો (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			જો (cc->isctype((unsigned અક્ષર)test))
				rval = RANGE_MATCH;
			તોડો;
		}
	}
	જો (cc->name == ખાલી) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	પાછા rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
સ્થિર પૂર્ણાંક fnmatch_ch(અચલ અક્ષર **pattern, અચલ અક્ષર **string, પૂર્ણાંક flags)
{
	અચલ અક્ષર * અચલ mismatch = *pattern;
	અચલ પૂર્ણાંક nocase = !!(flags & FNM_CASEFOLD);
	અચલ પૂર્ણાંક escape = !(flags & FNM_NOESCAPE);
	અચલ પૂર્ણાંક slash = !!(flags & FNM_PATHNAME);
	પૂર્ણાંક result = FNM_NOMATCH;
	અચલ અક્ષર *startch;
	પૂર્ણાંક negate;

	જો (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		જો (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		જો (**pattern == ']')
			જાઓ leadingclosebrace;

		જ્યારે (**pattern) {
			જો (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				પાછા (result ^ negate);
			}

			જો (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				જો (!**pattern)
					તોડો;
			}

			/* Patterns must terminate with ']' not '/' */
			જો (slash && (**pattern == '/'))
				તોડો;

			/* Match character classes. */
			પસંદગી (classmatch(*pattern, **string, nocase, pattern)) {
			સ્થિતિ RANGE_MATCH:
				result = 0;
				ચાલુ;
			સ્થિતિ RANGE_NOMATCH:
				/* Valid character class but no match. */
				ચાલુ;
			મૂળભૂત:
				/* Not a valid character class. */
				તોડો;
			}
			જો (!**pattern)
				તોડો;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			જો (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				જો (!**pattern || (slash && (**pattern == '/')))
					તોડો;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				જો ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				નહીંતર જો (nocase &&
				    (isupper((unsigned અક્ષર)**string) ||
				     isupper((unsigned અક્ષર)*startch) ||
				     isupper((unsigned અક્ષર)**pattern)) &&
				    (tolower((unsigned અક્ષર)**string) >=
				     tolower((unsigned અક્ષર)*startch)) &&
				    (tolower((unsigned અક્ષર)**string) <=
				     tolower((unsigned અક્ષર)**pattern)))
					result = 0;

				++*pattern;
				ચાલુ;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			જો ((**string == **pattern))
				result = 0;
			નહીંતર જો (nocase && (isupper((unsigned અક્ષર)**string) ||
			    isupper((unsigned અક્ષર)**pattern)) &&
			    (tolower((unsigned અક્ષર)**string) ==
			    tolower((unsigned અક્ષર)**pattern)))
				result = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		result = FNM_NOMATCH;
	} નહીંતર જો (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		જો (!**string || (slash && (**string == '/')))
			પાછા FNM_NOMATCH;
		result = 0;
		જાઓ fnmatch_ch_success;
	} નહીંતર જો (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	જો (**string == **pattern)
		result = 0;
	નહીંતર જો (nocase && (isupper((unsigned અક્ષર)**string) ||
	    isupper((unsigned અક્ષર)**pattern)) &&
	    (tolower((unsigned અક્ષર)**string) ==
	    tolower((unsigned અક્ષર)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	જો (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		પાછા result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	પાછા result;
}


પૂર્ણાંક fnmatch(અચલ અક્ષર *pattern, અચલ અક્ષર *string, પૂર્ણાંક flags)
{
	સ્થિર અચલ અક્ષર dummystring[2] = {' ', 0};
	અચલ પૂર્ણાંક escape = !(flags & FNM_NOESCAPE);
	અચલ પૂર્ણાંક slash = !!(flags & FNM_PATHNAME);
	અચલ પૂર્ણાંક leading_dir = !!(flags & FNM_LEADING_DIR);
	અચલ અક્ષર *dummyptr, *matchptr, *strendseg;
	પૂર્ણાંક wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	અચલ અક્ષર *strstartseg = ખાલી;
	અચલ અક્ષર *mismatch = ખાલી;
	પૂર્ણાંક matchlen = 0;

	જો (*pattern == '*')
		જાઓ firstsegment;

	જ્યારે (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		જો (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		જો (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		જો ((flags & FNM_PERIOD) && (*string == '.')) {
		    જો (*pattern == '.')
			    ++pattern;
		    નહીંતર જો (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    નહીંતર
			    પાછા FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		જો (slash) {
			strendseg = strchr(string, '/');
			જો (!strendseg)
				strendseg = strchr(string, '\0');
		} નહીંતર {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		જ્યારે (*pattern) {
			જો ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				તોડો;

			જો (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				તોડો;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			માટે (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				જો (*pattern == '*') {
					wild = 1;
				} નહીંતર જો (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				નહીંતર {  /* (string >= strendseg) && (*pattern == '?') */
					પાછા FNM_NOMATCH;
				}
			}

			જો (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				માટે (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					જો ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						જો (string + matchlen > strendseg)
							પાછા FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						તોડો;
					}

					જો (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						જો (string + matchlen > strendseg)
							પાછા FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						તોડો;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					જો (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} નહીંતર જો (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} નહીંતર {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			જ્યારે (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				જો (*pattern == '*')
					તોડો;

				જો (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					તોડો;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				જો (!fnmatch_ch(&pattern, &string, flags))
					ચાલુ;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				જો (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					જો (string + matchlen > strendseg)
						પાછા FNM_NOMATCH;

					pattern = mismatch;
					ચાલુ;
				} નહીંતર
					પાછા FNM_NOMATCH;
			}
		}

		જો (*string && !((slash || leading_dir) && (*string == '/')))
			પાછા FNM_NOMATCH;

		જો (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			પાછા FNM_NOMATCH;

		જો (leading_dir && !*pattern && *string == '/')
			પાછા 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	જો (!*string && !*pattern)
		પાછા 0;

	/* Pattern didn't match to the end of string. */
	પાછા FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
