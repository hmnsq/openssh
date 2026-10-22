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

#अन्तर्भाव "includes.h"
#यदि_अपरिभाषितम् HAVE_FNMATCH

#अन्तर्भाव <fnmatch.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <ctype.h>

#अन्तर्भाव "charclass.h"

#परिभाषय	RANGE_मेलनम्	1
#परिभाषय	RANGE_NOMATCH	0
#परिभाषय	RANGE_ERROR	(-1)

स्थिर पूर्णाङ्क
classmatch(ध्रुव वर्ण *आदर्शः, वर्ण test, पूर्णाङ्क foldcase, ध्रुव वर्ण **ep)
{
	ध्रुव वर्ण * ध्रुव mismatch = आदर्शः;
	ध्रुव वर्ण *colon;
	संरचना cclass *cc;
	पूर्णाङ्क rval = RANGE_NOMATCH;
	आकार_t len;

	यदि (आदर्शः[0] != '[' || आदर्शः[1] != ':') {
		*ep = mismatch;
		प्रत्यागम RANGE_ERROR;
	}
	आदर्शः += 2;

	यदि ((colon = strchr(आदर्शः, ':')) == रिक्त || colon[1] != ']') {
		*ep = mismatch;
		प्रत्यागम RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (आकार_t)(colon - आदर्शः);

	यदि (foldcase && वाक्ये_तुलय(आदर्शः, "upper:]", 7) == 0)
		आदर्शः = "lower:]";
	प्रति (cc = cclasses; cc->name != रिक्त; cc++) {
		यदि (!वाक्ये_तुलय(आदर्शः, cc->name, len) && cc->name[len] == '\0') {
			यदि (cc->isctype((अचिह्नित वर्ण)test))
				rval = RANGE_मेलनम्;
			भङ्ग;
		}
	}
	यदि (cc->name == रिक्त) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	प्रत्यागम rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
स्थिर पूर्णाङ्क fnmatch_ch(ध्रुव वर्ण **आदर्शः, ध्रुव वर्ण **string, पूर्णाङ्क flags)
{
	ध्रुव वर्ण * ध्रुव mismatch = *आदर्शः;
	ध्रुव पूर्णाङ्क nocase = !!(flags & FNM_CASEFOLD);
	ध्रुव पूर्णाङ्क escape = !(flags & FNM_NOESCAPE);
	ध्रुव पूर्णाङ्क slash = !!(flags & FNM_PATHNAME);
	पूर्णाङ्क परिणाम = FNM_NOMATCH;
	ध्रुव वर्ण *startch;
	पूर्णाङ्क negate;

	यदि (**आदर्शः == '[') {
		++*आदर्शः;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**आदर्शः == '!') || (**आदर्शः == '^');
		यदि (negate)
			++*आदर्शः;

		/* ']' is an ordinary char at the start of the range pattern */
		यदि (**आदर्शः == ']')
			गच्छ leadingclosebrace;

		यावत् (**आदर्शः) {
			यदि (**आदर्शः == ']') {
				++*आदर्शः;
				/* XXX: Fix for MBCS character width */
				++*string;
				प्रत्यागम (परिणाम ^ negate);
			}

			यदि (escape && (**आदर्शः == '\\')) {
				++*आदर्शः;

				/* Patterns must terminate with ']', not EOS */
				यदि (!**आदर्शः)
					भङ्ग;
			}

			/* Patterns must terminate with ']' not '/' */
			यदि (slash && (**आदर्शः == '/'))
				भङ्ग;

			/* Match character classes. */
			विकल्प (classmatch(*आदर्शः, **string, nocase, आदर्शः)) {
			पक्ष RANGE_मेलनम्:
				परिणाम = 0;
				अनुवर्त;
			पक्ष RANGE_NOMATCH:
				/* Valid character class but no match. */
				अनुवर्त;
			स्वभाव:
				/* Not a valid character class. */
				भङ्ग;
			}
			यदि (!**आदर्शः)
				भङ्ग;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			यदि (((*आदर्शः)[1] == '-') && ((*आदर्शः)[2] != ']')) {
				startch = *आदर्शः;
				*आदर्शः += (escape && ((*आदर्शः)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				यदि (!**आदर्शः || (slash && (**आदर्शः == '/')))
					भङ्ग;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				यदि ((**string >= *startch) && (**string <= **आदर्शः))
					परिणाम = 0;
				अन्यथा यदि (nocase &&
				    (isupper((अचिह्नित वर्ण)**string) ||
				     isupper((अचिह्नित वर्ण)*startch) ||
				     isupper((अचिह्नित वर्ण)**आदर्शः)) &&
				    (tolower((अचिह्नित वर्ण)**string) >=
				     tolower((अचिह्नित वर्ण)*startch)) &&
				    (tolower((अचिह्नित वर्ण)**string) <=
				     tolower((अचिह्नित वर्ण)**आदर्शः)))
					परिणाम = 0;

				++*आदर्शः;
				अनुवर्त;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			यदि ((**string == **आदर्शः))
				परिणाम = 0;
			अन्यथा यदि (nocase && (isupper((अचिह्नित वर्ण)**string) ||
			    isupper((अचिह्नित वर्ण)**आदर्शः)) &&
			    (tolower((अचिह्नित वर्ण)**string) ==
			    tolower((अचिह्नित वर्ण)**आदर्शः)))
				परिणाम = 0;

			++*आदर्शः;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*आदर्शः = mismatch;
		परिणाम = FNM_NOMATCH;
	} अन्यथा यदि (**आदर्शः == '?') {
		/* Optimize '?' match before unescaping **pattern */
		यदि (!**string || (slash && (**string == '/')))
			प्रत्यागम FNM_NOMATCH;
		परिणाम = 0;
		गच्छ fnmatch_ch_success;
	} अन्यथा यदि (escape && (**आदर्शः == '\\') && (*आदर्शः)[1]) {
		++*आदर्शः;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	यदि (**string == **आदर्शः)
		परिणाम = 0;
	अन्यथा यदि (nocase && (isupper((अचिह्नित वर्ण)**string) ||
	    isupper((अचिह्नित वर्ण)**आदर्शः)) &&
	    (tolower((अचिह्नित वर्ण)**string) ==
	    tolower((अचिह्नित वर्ण)**आदर्शः)))
		परिणाम = 0;

	/* Refuse to advance over trailing slash or NULs */
	यदि (**string == '\0' || **आदर्शः == '\0' ||
	    (slash && ((**string == '/') || (**आदर्शः == '/'))))
		प्रत्यागम परिणाम;

fnmatch_ch_success:
	++*आदर्शः;
	++*string;
	प्रत्यागम परिणाम;
}


पूर्णाङ्क fnmatch(ध्रुव वर्ण *आदर्शः, ध्रुव वर्ण *string, पूर्णाङ्क flags)
{
	स्थिर ध्रुव वर्ण dummystring[2] = {' ', 0};
	ध्रुव पूर्णाङ्क escape = !(flags & FNM_NOESCAPE);
	ध्रुव पूर्णाङ्क slash = !!(flags & FNM_PATHNAME);
	ध्रुव पूर्णाङ्क leading_dir = !!(flags & FNM_LEADING_DIR);
	ध्रुव वर्ण *dummyptr, *matchptr, *strendseg;
	पूर्णाङ्क wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	ध्रुव वर्ण *strstartseg = रिक्त;
	ध्रुव वर्ण *mismatch = रिक्त;
	पूर्णाङ्क matchlen = 0;

	यदि (*आदर्शः == '*')
		गच्छ firstsegment;

	यावत् (*आदर्शः && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		यदि (slash && escape && (*आदर्शः == '\\') && (आदर्शः[1] == '/'))
			++आदर्शः;
		यदि (slash && (*आदर्शः == '/') && (*string == '/')) {
			++आदर्शः;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		यदि ((flags & FNM_PERIOD) && (*string == '.')) {
		    यदि (*आदर्शः == '.')
			    ++आदर्शः;
		    अन्यथा यदि (escape && (*आदर्शः == '\\') && (आदर्शः[1] == '.'))
			    आदर्शः += 2;
		    अन्यथा
			    प्रत्यागम FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		यदि (slash) {
			strendseg = strchr(string, '/');
			यदि (!strendseg)
				strendseg = strchr(string, '\0');
		} अन्यथा {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		यावत् (*आदर्शः) {
			यदि ((string > strendseg) ||
			    ((string == strendseg) && (*आदर्शः != '*')))
				भङ्ग;

			यदि (slash && ((*आदर्शः == '/') ||
			    (escape && (*आदर्शः == '\\') && (आदर्शः[1] == '/'))))
				भङ्ग;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			प्रति (wild = 0; (*आदर्शः == '*') || (*आदर्शः == '?'); ++आदर्शः) {
				यदि (*आदर्शः == '*') {
					wild = 1;
				} अन्यथा यदि (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				अन्यथा {  /* (string >= strendseg) && (*pattern == '?') */
					प्रत्यागम FNM_NOMATCH;
				}
			}

			यदि (wild) {
				strstartseg = string;
				mismatch = आदर्शः;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				प्रति (matchptr = आदर्शः, matchlen = 0; 1; ++matchlen) {
					यदि ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						यदि (string + matchlen > strendseg)
							प्रत्यागम FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						भङ्ग;
					}

					यदि (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						यदि (string + matchlen > strendseg)
							प्रत्यागम FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						भङ्ग;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					यदि (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} अन्यथा यदि (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} अन्यथा {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			यावत् (*आदर्शः && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				यदि (*आदर्शः == '*')
					भङ्ग;

				यदि (slash && ((*string == '/') ||
				    (*आदर्शः == '/') || (escape &&
				    (*आदर्शः == '\\') && (आदर्शः[1] == '/'))))
					भङ्ग;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				यदि (!fnmatch_ch(&आदर्शः, &string, flags))
					अनुवर्त;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				यदि (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					यदि (string + matchlen > strendseg)
						प्रत्यागम FNM_NOMATCH;

					आदर्शः = mismatch;
					अनुवर्त;
				} अन्यथा
					प्रत्यागम FNM_NOMATCH;
			}
		}

		यदि (*string && !((slash || leading_dir) && (*string == '/')))
			प्रत्यागम FNM_NOMATCH;

		यदि (*आदर्शः && !(slash && ((*आदर्शः == '/') ||
		    (escape && (*आदर्शः == '\\') && (आदर्शः[1] == '/')))))
			प्रत्यागम FNM_NOMATCH;

		यदि (leading_dir && !*आदर्शः && *string == '/')
			प्रत्यागम 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	यदि (!*string && !*आदर्शः)
		प्रत्यागम 0;

	/* Pattern didn't match to the end of string. */
	प्रत्यागम FNM_NOMATCH;
}
#यदि_अन्तः /* HAVE_FNMATCH */
