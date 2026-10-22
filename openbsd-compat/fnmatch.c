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

#समावेश "includes.h"
#अगर_अघोषित HAVE_FNMATCH

#समावेश <fnmatch.h>
#समावेश <string.h>
#समावेश <ctype.h>

#समावेश "charclass.h"

#घोषणा	RANGE_MATCH	1
#घोषणा	RANGE_NOMATCH	0
#घोषणा	RANGE_ERROR	(-1)

अटल पूर्णांक
classmatch(स्थिर अक्षर *pattern, अक्षर test, पूर्णांक foldcase, स्थिर अक्षर **ep)
{
	स्थिर अक्षर * स्थिर mismatch = pattern;
	स्थिर अक्षर *colon;
	काष्ठा cclass *cc;
	पूर्णांक rval = RANGE_NOMATCH;
	माप_प्रकार len;

	अगर (pattern[0] != '[' || pattern[1] != ':') {
		*ep = mismatch;
		वापस RANGE_ERROR;
	}
	pattern += 2;

	अगर ((colon = म_अक्षर(pattern, ':')) == शून्य || colon[1] != ']') {
		*ep = mismatch;
		वापस RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (माप_प्रकार)(colon - pattern);

	अगर (foldcase && म_भेदन(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	क्रम (cc = cclasses; cc->name != शून्य; cc++) {
		अगर (!म_भेदन(pattern, cc->name, len) && cc->name[len] == '\0') {
			अगर (cc->isctype((अचिन्हित अक्षर)test))
				rval = RANGE_MATCH;
			अवरोध;
		}
	}
	अगर (cc->name == शून्य) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	वापस rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
अटल पूर्णांक fnmatch_ch(स्थिर अक्षर **pattern, स्थिर अक्षर **string, पूर्णांक flags)
{
	स्थिर अक्षर * स्थिर mismatch = *pattern;
	स्थिर पूर्णांक nocase = !!(flags & FNM_CASEFOLD);
	स्थिर पूर्णांक escape = !(flags & FNM_NOESCAPE);
	स्थिर पूर्णांक slash = !!(flags & FNM_PATHNAME);
	पूर्णांक परिणाम = FNM_NOMATCH;
	स्थिर अक्षर *startch;
	पूर्णांक negate;

	अगर (**pattern == '[') {
		++*pattern;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**pattern == '!') || (**pattern == '^');
		अगर (negate)
			++*pattern;

		/* ']' is an ordinary char at the start of the range pattern */
		अगर (**pattern == ']')
			जाओ leadingclosebrace;

		जबतक (**pattern) {
			अगर (**pattern == ']') {
				++*pattern;
				/* XXX: Fix for MBCS character width */
				++*string;
				वापस (परिणाम ^ negate);
			}

			अगर (escape && (**pattern == '\\')) {
				++*pattern;

				/* Patterns must terminate with ']', not EOS */
				अगर (!**pattern)
					अवरोध;
			}

			/* Patterns must terminate with ']' not '/' */
			अगर (slash && (**pattern == '/'))
				अवरोध;

			/* Match character classes. */
			चयन (classmatch(*pattern, **string, nocase, pattern)) {
			हाल RANGE_MATCH:
				परिणाम = 0;
				जारी;
			हाल RANGE_NOMATCH:
				/* Valid character class but no match. */
				जारी;
			शेष:
				/* Not a valid character class. */
				अवरोध;
			}
			अगर (!**pattern)
				अवरोध;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			अगर (((*pattern)[1] == '-') && ((*pattern)[2] != ']')) {
				startch = *pattern;
				*pattern += (escape && ((*pattern)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				अगर (!**pattern || (slash && (**pattern == '/')))
					अवरोध;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				अगर ((**string >= *startch) && (**string <= **pattern))
					परिणाम = 0;
				अन्यथा अगर (nocase &&
				    (है_बड़ा((अचिन्हित अक्षर)**string) ||
				     है_बड़ा((अचिन्हित अक्षर)*startch) ||
				     है_बड़ा((अचिन्हित अक्षर)**pattern)) &&
				    (छोटे((अचिन्हित अक्षर)**string) >=
				     छोटे((अचिन्हित अक्षर)*startch)) &&
				    (छोटे((अचिन्हित अक्षर)**string) <=
				     छोटे((अचिन्हित अक्षर)**pattern)))
					परिणाम = 0;

				++*pattern;
				जारी;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			अगर ((**string == **pattern))
				परिणाम = 0;
			अन्यथा अगर (nocase && (है_बड़ा((अचिन्हित अक्षर)**string) ||
			    है_बड़ा((अचिन्हित अक्षर)**pattern)) &&
			    (छोटे((अचिन्हित अक्षर)**string) ==
			    छोटे((अचिन्हित अक्षर)**pattern)))
				परिणाम = 0;

			++*pattern;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*pattern = mismatch;
		परिणाम = FNM_NOMATCH;
	} अन्यथा अगर (**pattern == '?') {
		/* Optimize '?' match before unescaping **pattern */
		अगर (!**string || (slash && (**string == '/')))
			वापस FNM_NOMATCH;
		परिणाम = 0;
		जाओ fnmatch_ch_success;
	} अन्यथा अगर (escape && (**pattern == '\\') && (*pattern)[1]) {
		++*pattern;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	अगर (**string == **pattern)
		परिणाम = 0;
	अन्यथा अगर (nocase && (है_बड़ा((अचिन्हित अक्षर)**string) ||
	    है_बड़ा((अचिन्हित अक्षर)**pattern)) &&
	    (छोटे((अचिन्हित अक्षर)**string) ==
	    छोटे((अचिन्हित अक्षर)**pattern)))
		परिणाम = 0;

	/* Refuse to advance over trailing slash or NULs */
	अगर (**string == '\0' || **pattern == '\0' ||
	    (slash && ((**string == '/') || (**pattern == '/'))))
		वापस परिणाम;

fnmatch_ch_success:
	++*pattern;
	++*string;
	वापस परिणाम;
}


पूर्णांक fnmatch(स्थिर अक्षर *pattern, स्थिर अक्षर *string, पूर्णांक flags)
{
	अटल स्थिर अक्षर dummystring[2] = {' ', 0};
	स्थिर पूर्णांक escape = !(flags & FNM_NOESCAPE);
	स्थिर पूर्णांक slash = !!(flags & FNM_PATHNAME);
	स्थिर पूर्णांक leading_dir = !!(flags & FNM_LEADING_DIR);
	स्थिर अक्षर *dummyptr, *matchptr, *strendseg;
	पूर्णांक wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	स्थिर अक्षर *strstartseg = शून्य;
	स्थिर अक्षर *mismatch = शून्य;
	पूर्णांक matchlen = 0;

	अगर (*pattern == '*')
		जाओ firstsegment;

	जबतक (*pattern && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		अगर (slash && escape && (*pattern == '\\') && (pattern[1] == '/'))
			++pattern;
		अगर (slash && (*pattern == '/') && (*string == '/')) {
			++pattern;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		अगर ((flags & FNM_PERIOD) && (*string == '.')) {
		    अगर (*pattern == '.')
			    ++pattern;
		    अन्यथा अगर (escape && (*pattern == '\\') && (pattern[1] == '.'))
			    pattern += 2;
		    अन्यथा
			    वापस FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		अगर (slash) {
			strendseg = म_अक्षर(string, '/');
			अगर (!strendseg)
				strendseg = म_अक्षर(string, '\0');
		} अन्यथा {
			strendseg = म_अक्षर(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		जबतक (*pattern) {
			अगर ((string > strendseg) ||
			    ((string == strendseg) && (*pattern != '*')))
				अवरोध;

			अगर (slash && ((*pattern == '/') ||
			    (escape && (*pattern == '\\') && (pattern[1] == '/'))))
				अवरोध;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			क्रम (wild = 0; (*pattern == '*') || (*pattern == '?'); ++pattern) {
				अगर (*pattern == '*') {
					wild = 1;
				} अन्यथा अगर (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				अन्यथा {  /* (string >= strendseg) && (*pattern == '?') */
					वापस FNM_NOMATCH;
				}
			}

			अगर (wild) {
				strstartseg = string;
				mismatch = pattern;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				क्रम (matchptr = pattern, matchlen = 0; 1; ++matchlen) {
					अगर ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						अगर (string + matchlen > strendseg)
							वापस FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						अवरोध;
					}

					अगर (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						अगर (string + matchlen > strendseg)
							वापस FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						अवरोध;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					अगर (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} अन्यथा अगर (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} अन्यथा {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			जबतक (*pattern && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				अगर (*pattern == '*')
					अवरोध;

				अगर (slash && ((*string == '/') ||
				    (*pattern == '/') || (escape &&
				    (*pattern == '\\') && (pattern[1] == '/'))))
					अवरोध;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				अगर (!fnmatch_ch(&pattern, &string, flags))
					जारी;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				अगर (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					अगर (string + matchlen > strendseg)
						वापस FNM_NOMATCH;

					pattern = mismatch;
					जारी;
				} अन्यथा
					वापस FNM_NOMATCH;
			}
		}

		अगर (*string && !((slash || leading_dir) && (*string == '/')))
			वापस FNM_NOMATCH;

		अगर (*pattern && !(slash && ((*pattern == '/') ||
		    (escape && (*pattern == '\\') && (pattern[1] == '/')))))
			वापस FNM_NOMATCH;

		अगर (leading_dir && !*pattern && *string == '/')
			वापस 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	अगर (!*string && !*pattern)
		वापस 0;

	/* Pattern didn't match to the end of string. */
	वापस FNM_NOMATCH;
}
#पूर्ण_अगर /* HAVE_FNMATCH */
