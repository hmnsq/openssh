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

#അന്തര്ഭാവ "includes.h"
#ifndef HAVE_FNMATCH

#അന്തര്ഭാവ <fnmatch.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <ctype.h>

#അന്തര്ഭാവ "charclass.h"

#define	RANGE_MATCH	1
#define	RANGE_NOMATCH	0
#define	RANGE_ERROR	(-1)

സ്ഥിതം പൂർണ്ണസംഖ്യ
classmatch(സ്ഥിരം അക്ഷരം *pattern, അക്ഷരം test, പൂർണ്ണസംഖ്യ foldcase, സ്ഥിരം അക്ഷരം **ep)
{
	സ്ഥിരം അക്ഷരം * സ്ഥിരം mismatch = pattern;
	സ്ഥിരം അക്ഷരം *colon;
	ഘടന cclass *cc;
	പൂർണ്ണസംഖ്യ rval = RANGE_NOMATCH;
	size_t len;

	എങ്കിൽ (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		തിരികെ RANGE_ERROR;
	}
	pattern += 2;

	എങ്കിൽ ((colon = strchr(pattern, ':')) == ശൂന്യ || colon[1] != ']') {
		*ep = mismatch;
		തിരികെ RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	എങ്കിൽ (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	വേണ്ടി (cc = cclasses; cc->name != ശൂന്യ; cc++) {
		എങ്കിൽ (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			എങ്കിൽ (cc->isctype((unsigned അക്ഷരം)test))
				rval = RANGE_MATCH;
			നിർത്തുക;
		}
	}
	എങ്കിൽ (cc->name == ശൂന്യ) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	തിരികെ rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ fnmatch_ch(സ്ഥിരം അക്ഷരം **pattern, സ്ഥിരം അക്ഷരം **string, പൂർണ്ണസംഖ്യ flags)
{
	സ്ഥിരം അക്ഷരം * സ്ഥിരം mismatch = *pattern;
	സ്ഥിരം പൂർണ്ണസംഖ്യ nocase = !!(flags & FNM_CASEFOLD);
	സ്ഥിരം പൂർണ്ണസംഖ്യ escape = !(flags & FNM_NOESCAPE);
	സ്ഥിരം പൂർണ്ണസംഖ്യ slash = !!(flags & FNM_PATHNAME);
	പൂർണ്ണസംഖ്യ result = FNM_NOMATCH;
	സ്ഥിരം അക്ഷരം *startch;
	പൂർണ്ണസംഖ്യ negate;

	എങ്കിൽ (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		എങ്കിൽ (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		എങ്കിൽ (**pattern == ']')
			പോകുക leadingclosebrace;

		ആകുമ്പോൾ (**pattern) {
			എങ്കിൽ (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				തിരികെ (result ^ negate);
			}

			എങ്കിൽ (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				എങ്കിൽ (!**pattern)
					നിർത്തുക;
			}

			/* Patterns must terminate with ']' not '/' */
			എങ്കിൽ (slash && (**pattern == '/'))
				നിർത്തുക;

			/* Match character classes. */
			തിരഞ്ഞെടുപ്പ് (classmatch(*pattern, **string, nocase, pattern)) {
			അവസ്ഥ RANGE_MATCH:
				result = 0;
				തുടരുക;
			അവസ്ഥ RANGE_NOMATCH:
				/* Valid character class but no match. */
				തുടരുക;
			സ്ഥിരസ്ഥിതി:
				/* Not a valid character class. */
				നിർത്തുക;
			}
			എങ്കിൽ (!**pattern)
				നിർത്തുക;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			എങ്കിൽ (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				എങ്കിൽ (!**pattern || (slash && (**pattern == '/')))
					നിർത്തുക;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				എങ്കിൽ ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				അല്ലെങ്കിൽ എങ്കിൽ (nocase &&
				    (isupper((unsigned അക്ഷരം)**string) ||
				     isupper((unsigned അക്ഷരം)*startch) ||
				     isupper((unsigned അക്ഷരം)**pattern)) &&
				    (tolower((unsigned അക്ഷരം)**string) >=
				     tolower((unsigned അക്ഷരം)*startch)) &&
				    (tolower((unsigned അക്ഷരം)**string) <=
				     tolower((unsigned അക്ഷരം)**pattern)))
					result = 0;

				++*pattern;
				തുടരുക;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			എങ്കിൽ ((**string == **pattern))
				result = 0;
			അല്ലെങ്കിൽ എങ്കിൽ (nocase && (isupper((unsigned അക്ഷരം)**string) ||
			    isupper((unsigned അക്ഷരം)**pattern)) &&
			    (tolower((unsigned അക്ഷരം)**string) ==
			    tolower((unsigned അക്ഷരം)**pattern)))
				result = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		result = FNM_NOMATCH;
	} അല്ലെങ്കിൽ എങ്കിൽ (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		എങ്കിൽ (!**string || (slash && (**string == '/')))
			തിരികെ FNM_NOMATCH;
		result = 0;
		പോകുക fnmatch_ch_success;
	} അല്ലെങ്കിൽ എങ്കിൽ (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	എങ്കിൽ (**string == **pattern)
		result = 0;
	അല്ലെങ്കിൽ എങ്കിൽ (nocase && (isupper((unsigned അക്ഷരം)**string) ||
	    isupper((unsigned അക്ഷരം)**pattern)) &&
	    (tolower((unsigned അക്ഷരം)**string) ==
	    tolower((unsigned അക്ഷരം)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	എങ്കിൽ (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		തിരികെ result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	തിരികെ result;
}


പൂർണ്ണസംഖ്യ fnmatch(സ്ഥിരം അക്ഷരം *pattern, സ്ഥിരം അക്ഷരം *string, പൂർണ്ണസംഖ്യ flags)
{
	സ്ഥിതം സ്ഥിരം അക്ഷരം dummystring[2] = {' ', 0};
	സ്ഥിരം പൂർണ്ണസംഖ്യ escape = !(flags & FNM_NOESCAPE);
	സ്ഥിരം പൂർണ്ണസംഖ്യ slash = !!(flags & FNM_PATHNAME);
	സ്ഥിരം പൂർണ്ണസംഖ്യ leading_dir = !!(flags & FNM_LEADING_DIR);
	സ്ഥിരം അക്ഷരം *dummyptr, *matchptr, *strendseg;
	പൂർണ്ണസംഖ്യ wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	സ്ഥിരം അക്ഷരം *strstartseg = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *mismatch = ശൂന്യ;
	പൂർണ്ണസംഖ്യ matchlen = 0;

	എങ്കിൽ (*pattern == '*')
		പോകുക firstsegment;

	ആകുമ്പോൾ (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		എങ്കിൽ (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		എങ്കിൽ (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		എങ്കിൽ ((flags & FNM_PERIOD) && (*string == '.')) {
		    എങ്കിൽ (*pattern == '.')
			    ++pattern;
		    അല്ലെങ്കിൽ എങ്കിൽ (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    അല്ലെങ്കിൽ
			    തിരികെ FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		എങ്കിൽ (slash) {
			strendseg = strchr(string, '/');
			എങ്കിൽ (!strendseg)
				strendseg = strchr(string, '\0');
		} അല്ലെങ്കിൽ {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		ആകുമ്പോൾ (*pattern) {
			എങ്കിൽ ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				നിർത്തുക;

			എങ്കിൽ (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				നിർത്തുക;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			വേണ്ടി (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				എങ്കിൽ (*pattern == '*') {
					wild = 1;
				} അല്ലെങ്കിൽ എങ്കിൽ (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				അല്ലെങ്കിൽ {  /* (string >= strendseg) && (*pattern == '?') */
					തിരികെ FNM_NOMATCH;
				}
			}

			എങ്കിൽ (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				വേണ്ടി (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					എങ്കിൽ ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						എങ്കിൽ (string + matchlen > strendseg)
							തിരികെ FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						നിർത്തുക;
					}

					എങ്കിൽ (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						എങ്കിൽ (string + matchlen > strendseg)
							തിരികെ FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						നിർത്തുക;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					എങ്കിൽ (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} അല്ലെങ്കിൽ എങ്കിൽ (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} അല്ലെങ്കിൽ {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			ആകുമ്പോൾ (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				എങ്കിൽ (*pattern == '*')
					നിർത്തുക;

				എങ്കിൽ (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					നിർത്തുക;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				എങ്കിൽ (!fnmatch_ch(&pattern, &string, flags))
					തുടരുക;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				എങ്കിൽ (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					എങ്കിൽ (string + matchlen > strendseg)
						തിരികെ FNM_NOMATCH;

					pattern = mismatch;
					തുടരുക;
				} അല്ലെങ്കിൽ
					തിരികെ FNM_NOMATCH;
			}
		}

		എങ്കിൽ (*string && !((slash || leading_dir) && (*string == '/')))
			തിരികെ FNM_NOMATCH;

		എങ്കിൽ (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			തിരികെ FNM_NOMATCH;

		എങ്കിൽ (leading_dir && !*pattern && *string == '/')
			തിരികെ 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	എങ്കിൽ (!*string && !*pattern)
		തിരികെ 0;

	/* Pattern didn't match to the end of string. */
	തിരികെ FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
