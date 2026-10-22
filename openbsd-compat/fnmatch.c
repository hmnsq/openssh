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
#ifndef HAVE_FNMATCH

#अन्तर्भाव <fnmatch.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <ctype.h>

#अन्तर्भाव "charclass.h"

#define	RANGE_MATCH	1
#define	RANGE_NOMATCH	0
#define	RANGE_ERROR	(-1)

स्थिर पूर्णांक
classmatch(स्थिरांक अक्षर *pattern, अक्षर test, पूर्णांक foldcase, स्थिरांक अक्षर **ep)
{
	स्थिरांक अक्षर * स्थिरांक mismatch = pattern;
	स्थिरांक अक्षर *colon;
	संरचना cclass *cc;
	पूर्णांक rval = RANGE_NOMATCH;
	माप_प्रकार len;

	जर (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		परत RANGE_ERROR;
	}
	pattern += 2;

	जर ((colon = म_अक्षर(pattern, ':')) == रिक्त || colon[1] != ']') {
		*ep = mismatch;
		परत RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (माप_प्रकार)(colon - pattern);

	जर (foldcase && म_भेदन(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	साठी (cc = cclasses; cc->name != रिक्त; cc++) {
		जर (!म_भेदन(pattern, cc->name, len) && cc->name[len] == '\0') {
			जर (cc->isctype((अचिन्हित अक्षर)test))
				rval = RANGE_MATCH;
			थांबा;
		}
	}
	जर (cc->name == रिक्त) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	परत rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
स्थिर पूर्णांक fnmatch_ch(स्थिरांक अक्षर **pattern, स्थिरांक अक्षर **string, पूर्णांक flags)
{
	स्थिरांक अक्षर * स्थिरांक mismatch = *pattern;
	स्थिरांक पूर्णांक nocase = !!(flags & FNM_CASEFOLD);
	स्थिरांक पूर्णांक escape = !(flags & FNM_NOESCAPE);
	स्थिरांक पूर्णांक slash = !!(flags & FNM_PATHNAME);
	पूर्णांक result = FNM_NOMATCH;
	स्थिरांक अक्षर *startch;
	पूर्णांक negate;

	जर (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		जर (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		जर (**pattern == ']')
			जा leadingclosebrace;

		पर्यंत (**pattern) {
			जर (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				परत (result ^ negate);
			}

			जर (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				जर (!**pattern)
					थांबा;
			}

			/* Patterns must terminate with ']' not '/' */
			जर (slash && (**pattern == '/'))
				थांबा;

			/* Match character classes. */
			निवड (classmatch(*pattern, **string, nocase, pattern)) {
			स्थिती RANGE_MATCH:
				result = 0;
				सुरूठेवा;
			स्थिती RANGE_NOMATCH:
				/* Valid character class but no match. */
				सुरूठेवा;
			पूर्वनिर्धारित:
				/* Not a valid character class. */
				थांबा;
			}
			जर (!**pattern)
				थांबा;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			जर (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				जर (!**pattern || (slash && (**pattern == '/')))
					थांबा;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				जर ((**string >= *startch) && (**string <= **pattern))
					result = 0;
				अन्यथा जर (nocase &&
				    (है_बड़ा((अचिन्हित अक्षर)**string) ||
				     है_बड़ा((अचिन्हित अक्षर)*startch) ||
				     है_बड़ा((अचिन्हित अक्षर)**pattern)) &&
				    (छोटे((अचिन्हित अक्षर)**string) >=
				     छोटे((अचिन्हित अक्षर)*startch)) &&
				    (छोटे((अचिन्हित अक्षर)**string) <=
				     छोटे((अचिन्हित अक्षर)**pattern)))
					result = 0;

				++*pattern;
				सुरूठेवा;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			जर ((**string == **pattern))
				result = 0;
			अन्यथा जर (nocase && (है_बड़ा((अचिन्हित अक्षर)**string) ||
			    है_बड़ा((अचिन्हित अक्षर)**pattern)) &&
			    (छोटे((अचिन्हित अक्षर)**string) ==
			    छोटे((अचिन्हित अक्षर)**pattern)))
				result = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		result = FNM_NOMATCH;
	} अन्यथा जर (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		जर (!**string || (slash && (**string == '/')))
			परत FNM_NOMATCH;
		result = 0;
		जा fnmatch_ch_success;
	} अन्यथा जर (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	जर (**string == **pattern)
		result = 0;
	अन्यथा जर (nocase && (है_बड़ा((अचिन्हित अक्षर)**string) ||
	    है_बड़ा((अचिन्हित अक्षर)**pattern)) &&
	    (छोटे((अचिन्हित अक्षर)**string) ==
	    छोटे((अचिन्हित अक्षर)**pattern)))
		result = 0;

	/* Refuse to advance over trailing slash or NULs */
	जर (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		परत result;

fnmatch_ch_success:
	++*pattern;
	++*string;
	परत result;
}


पूर्णांक fnmatch(स्थिरांक अक्षर *pattern, स्थिरांक अक्षर *string, पूर्णांक flags)
{
	स्थिर स्थिरांक अक्षर dummystring[2] = {' ', 0};
	स्थिरांक पूर्णांक escape = !(flags & FNM_NOESCAPE);
	स्थिरांक पूर्णांक slash = !!(flags & FNM_PATHNAME);
	स्थिरांक पूर्णांक leading_dir = !!(flags & FNM_LEADING_DIR);
	स्थिरांक अक्षर *dummyptr, *matchptr, *strendseg;
	पूर्णांक wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	स्थिरांक अक्षर *strstartseg = रिक्त;
	स्थिरांक अक्षर *mismatch = रिक्त;
	पूर्णांक matchlen = 0;

	जर (*pattern == '*')
		जा firstsegment;

	पर्यंत (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		जर (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		जर (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		जर ((flags & FNM_PERIOD) && (*string == '.')) {
		    जर (*pattern == '.')
			    ++pattern;
		    अन्यथा जर (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    अन्यथा
			    परत FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		जर (slash) {
			strendseg = म_अक्षर(string, '/');
			जर (!strendseg)
				strendseg = म_अक्षर(string, '\0');
		} अन्यथा {
			strendseg = म_अक्षर(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		पर्यंत (*pattern) {
			जर ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				थांबा;

			जर (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				थांबा;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			साठी (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				जर (*pattern == '*') {
					wild = 1;
				} अन्यथा जर (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				अन्यथा {  /* (string >= strendseg) && (*pattern == '?') */
					परत FNM_NOMATCH;
				}
			}

			जर (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				साठी (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					जर ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						जर (string + matchlen > strendseg)
							परत FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						थांबा;
					}

					जर (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						जर (string + matchlen > strendseg)
							परत FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						थांबा;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					जर (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} अन्यथा जर (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} अन्यथा {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			पर्यंत (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				जर (*pattern == '*')
					थांबा;

				जर (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					थांबा;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				जर (!fnmatch_ch(&pattern, &string, flags))
					सुरूठेवा;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				जर (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					जर (string + matchlen > strendseg)
						परत FNM_NOMATCH;

					pattern = mismatch;
					सुरूठेवा;
				} अन्यथा
					परत FNM_NOMATCH;
			}
		}

		जर (*string && !((slash || leading_dir) && (*string == '/')))
			परत FNM_NOMATCH;

		जर (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			परत FNM_NOMATCH;

		जर (leading_dir && !*pattern && *string == '/')
			परत 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	जर (!*string && !*pattern)
		परत 0;

	/* Pattern didn't match to the end of string. */
	परत FNM_NOMATCH;
}
#endif /* HAVE_FNMATCH */
