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

#అన్తర్భావ "includes.h"
#నిర్వచితం_కాకపోతే HAVE_FNMATCH

#అన్తర్భావ <fnmatch.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <ctype.h>

#అన్తర్భావ "charclass.h"

#నిర్వచించు	RANGE_సరిపోలిక	1
#నిర్వచించు	RANGE_NOMATCH	0
#నిర్వచించు	RANGE_ERROR	(-1)

స్థిర పూర్ణాంకం
classmatch(స్థిరరాశి అక్షరం *నమూనా, అక్షరం test, పూర్ణాంకం foldcase, స్థిరరాశి అక్షరం **ep)
{
	స్థిరరాశి అక్షరం * స్థిరరాశి mismatch = నమూనా;
	స్థిరరాశి అక్షరం *colon;
	నిర్మాణం cclass *cc;
	పూర్ణాంకం rval = RANGE_NOMATCH;
	కొలత_t len;

	ఒకవేళ (నమూనా[0] != '[' || నమూనా[1] != ':') {
		*ep = mismatch;
		తిరిగి RANGE_ERROR;
	}
	నమూనా += 2;

	ఒకవేళ ((colon = strchr(నమూనా, ':')) == ఖాళీ || colon[1] != ']') {
		*ep = mismatch;
		తిరిగి RANGE_ERROR;
	}
	*ep = colon + 2;
	len = (కొలత_t)(colon - నమూనా);

	ఒకవేళ (foldcase && అక్షరశ్రేణి_పోలిక(నమూనా, "upper:]", 7) == 0)
		నమూనా = "lower:]";
	కొరకు (cc = cclasses; cc->name != ఖాళీ; cc++) {
		ఒకవేళ (!అక్షరశ్రేణి_పోలిక(నమూనా, cc->name, len) && cc->name[len] == '\0') {
			ఒకవేళ (cc->isctype((గుర్తులేని అక్షరం)test))
				rval = RANGE_సరిపోలిక;
			ఆపు;
		}
	}
	ఒకవేళ (cc->name == ఖాళీ) {
		/* invalid character class, treat as normal text */
		*ep = mismatch;
		rval = RANGE_ERROR;
	}
	తిరిగి rval;
}

/* Most MBCS/collation/case issues handled here.  Wildcard '*' is not handled.
 * EOS '\0' and the FNM_PATHNAME '/' delimiters are not advanced over,
 * however the "\/" sequence is advanced to '/'.
 *
 * Both pattern and string are **char to support pointer increment of arbitrary
 * multibyte characters for the given locale, in a later iteration of this code
 */
స్థిర పూర్ణాంకం fnmatch_ch(స్థిరరాశి అక్షరం **నమూనా, స్థిరరాశి అక్షరం **string, పూర్ణాంకం flags)
{
	స్థిరరాశి అక్షరం * స్థిరరాశి mismatch = *నమూనా;
	స్థిరరాశి పూర్ణాంకం nocase = !!(flags & FNM_CASEFOLD);
	స్థిరరాశి పూర్ణాంకం escape = !(flags & FNM_NOESCAPE);
	స్థిరరాశి పూర్ణాంకం slash = !!(flags & FNM_PATHNAME);
	పూర్ణాంకం ఫలితం = FNM_NOMATCH;
	స్థిరరాశి అక్షరం *startch;
	పూర్ణాంకం negate;

	ఒకవేళ (**నమూనా == '[') {
		++*నమూనా;

		/* Handle negation, either leading ! or ^ operators */
		negate = (**నమూనా == '!') || (**నమూనా == '^');
		ఒకవేళ (negate)
			++*నమూనా;

		/* ']' is an ordinary char at the start of the range pattern */
		ఒకవేళ (**నమూనా == ']')
			వెళ్ళు leadingclosebrace;

		అయితే (**నమూనా) {
			ఒకవేళ (**నమూనా == ']') {
				++*నమూనా;
				/* XXX: Fix for MBCS character width */
				++*string;
				తిరిగి (ఫలితం ^ negate);
			}

			ఒకవేళ (escape && (**నమూనా == '\\')) {
				++*నమూనా;

				/* Patterns must terminate with ']', not EOS */
				ఒకవేళ (!**నమూనా)
					ఆపు;
			}

			/* Patterns must terminate with ']' not '/' */
			ఒకవేళ (slash && (**నమూనా == '/'))
				ఆపు;

			/* Match character classes. */
			ఎంపిక (classmatch(*నమూనా, **string, nocase, నమూనా)) {
			స్థితి RANGE_సరిపోలిక:
				ఫలితం = 0;
				కొనసాగు;
			స్థితి RANGE_NOMATCH:
				/* Valid character class but no match. */
				కొనసాగు;
			అప్రమేయ:
				/* Not a valid character class. */
				ఆపు;
			}
			ఒకవేళ (!**నమూనా)
				ఆపు;

leadingclosebrace:
			/* Look at only well-formed range patterns;
			 * "x-]" is not allowed unless escaped ("x-\]")
			 * XXX: Fix for locale/MBCS character width
			 */
			ఒకవేళ (((*నమూనా)[1] == '-') && ((*నమూనా)[2] != ']')) {
				startch = *నమూనా;
				*నమూనా += (escape && ((*నమూనా)[2] == '\\')) ? 3 : 2;

				/*
				 * NOT a properly balanced [expr] pattern, EOS
				 * terminated or ranges containing a slash in
				 * FNM_PATHNAME mode pattern fall out to to the
				 * rewind and test '[' literal code path.
				 */
				ఒకవేళ (!**నమూనా || (slash && (**నమూనా == '/')))
					ఆపు;

				/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
				ఒకవేళ ((**string >= *startch) && (**string <= **నమూనా))
					ఫలితం = 0;
				లేకపోతే ఒకవేళ (nocase &&
				    (isupper((గుర్తులేని అక్షరం)**string) ||
				     isupper((గుర్తులేని అక్షరం)*startch) ||
				     isupper((గుర్తులేని అక్షరం)**నమూనా)) &&
				    (tolower((గుర్తులేని అక్షరం)**string) >=
				     tolower((గుర్తులేని అక్షరం)*startch)) &&
				    (tolower((గుర్తులేని అక్షరం)**string) <=
				     tolower((గుర్తులేని అక్షరం)**నమూనా)))
					ఫలితం = 0;

				++*నమూనా;
				కొనసాగు;
			}

			/* XXX: handle locale/MBCS comparison, advance by MBCS char width */
			ఒకవేళ ((**string == **నమూనా))
				ఫలితం = 0;
			లేకపోతే ఒకవేళ (nocase && (isupper((గుర్తులేని అక్షరం)**string) ||
			    isupper((గుర్తులేని అక్షరం)**నమూనా)) &&
			    (tolower((గుర్తులేని అక్షరం)**string) ==
			    tolower((గుర్తులేని అక్షరం)**నమూనా)))
				ఫలితం = 0;

			++*నమూనా;
		}
		/*
		 * NOT a properly balanced [expr] pattern;
		 * Rewind and reset result to test '[' literal
		 */
		*నమూనా = mismatch;
		ఫలితం = FNM_NOMATCH;
	} లేకపోతే ఒకవేళ (**నమూనా == '?') {
		/* Optimize '?' match before unescaping **pattern */
		ఒకవేళ (!**string || (slash && (**string == '/')))
			తిరిగి FNM_NOMATCH;
		ఫలితం = 0;
		వెళ్ళు fnmatch_ch_success;
	} లేకపోతే ఒకవేళ (escape && (**నమూనా == '\\') && (*నమూనా)[1]) {
		++*నమూనా;
	}

	/* XXX: handle locale/MBCS comparison, advance by the MBCS char width */
	ఒకవేళ (**string == **నమూనా)
		ఫలితం = 0;
	లేకపోతే ఒకవేళ (nocase && (isupper((గుర్తులేని అక్షరం)**string) ||
	    isupper((గుర్తులేని అక్షరం)**నమూనా)) &&
	    (tolower((గుర్తులేని అక్షరం)**string) ==
	    tolower((గుర్తులేని అక్షరం)**నమూనా)))
		ఫలితం = 0;

	/* Refuse to advance over trailing slash or NULs */
	ఒకవేళ (**string == '\0' || **నమూనా == '\0' ||
	    (slash && ((**string == '/') || (**నమూనా == '/'))))
		తిరిగి ఫలితం;

fnmatch_ch_success:
	++*నమూనా;
	++*string;
	తిరిగి ఫలితం;
}


పూర్ణాంకం fnmatch(స్థిరరాశి అక్షరం *నమూనా, స్థిరరాశి అక్షరం *string, పూర్ణాంకం flags)
{
	స్థిర స్థిరరాశి అక్షరం dummystring[2] = {' ', 0};
	స్థిరరాశి పూర్ణాంకం escape = !(flags & FNM_NOESCAPE);
	స్థిరరాశి పూర్ణాంకం slash = !!(flags & FNM_PATHNAME);
	స్థిరరాశి పూర్ణాంకం leading_dir = !!(flags & FNM_LEADING_DIR);
	స్థిరరాశి అక్షరం *dummyptr, *matchptr, *strendseg;
	పూర్ణాంకం wild;
	/* For '*' wild processing only; suppress 'used before initialization'
	 * warnings with dummy initialization values;
	 */
	స్థిరరాశి అక్షరం *strstartseg = ఖాళీ;
	స్థిరరాశి అక్షరం *mismatch = ఖాళీ;
	పూర్ణాంకం matchlen = 0;

	ఒకవేళ (*నమూనా == '*')
		వెళ్ళు firstsegment;

	అయితే (*నమూనా && *string) {
		/*
		 * Pre-decode "\/" which has no special significance, and
		 * match balanced slashes, starting a new segment pattern.
		 */
		ఒకవేళ (slash && escape && (*నమూనా == '\\') && (నమూనా[1] == '/'))
			++నమూనా;
		ఒకవేళ (slash && (*నమూనా == '/') && (*string == '/')) {
			++నమూనా;
			++string;
		}

firstsegment:
		/*
		 * At the beginning of each segment, validate leading period
		 * behavior.
		 */
		ఒకవేళ ((flags & FNM_PERIOD) && (*string == '.')) {
		    ఒకవేళ (*నమూనా == '.')
			    ++నమూనా;
		    లేకపోతే ఒకవేళ (escape && (*నమూనా == '\\') && (నమూనా[1] == '.'))
			    నమూనా += 2;
		    లేకపోతే
			    తిరిగి FNM_NOMATCH;
		    ++string;
		}

		/*
		 * Determine the end of string segment.  Presumes '/'
		 * character is unique, not composite in any MBCS encoding
		 */
		ఒకవేళ (slash) {
			strendseg = strchr(string, '/');
			ఒకవేళ (!strendseg)
				strendseg = strchr(string, '\0');
		} లేకపోతే {
			strendseg = strchr(string, '\0');
		}

		/*
		 * Allow pattern '*' to be consumed even with no remaining
		 * string to match.
		 */
		అయితే (*నమూనా) {
			ఒకవేళ ((string > strendseg) ||
			    ((string == strendseg) && (*నమూనా != '*')))
				ఆపు;

			ఒకవేళ (slash && ((*నమూనా == '/') ||
			    (escape && (*నమూనా == '\\') && (నమూనా[1] == '/'))))
				ఆపు;

			/*
			 * Reduce groups of '*' and '?' to n '?' matches
			 * followed by one '*' test for simplicity.
			 */
			కొరకు (wild = 0; (*నమూనా == '*') || (*నమూనా == '?'); ++నమూనా) {
				ఒకవేళ (*నమూనా == '*') {
					wild = 1;
				} లేకపోతే ఒకవేళ (string < strendseg) {  /* && (*pattern == '?') */
					/* XXX: Advance 1 char for MBCS locale */
					++string;
				}
				లేకపోతే {  /* (string >= strendseg) && (*pattern == '?') */
					తిరిగి FNM_NOMATCH;
				}
			}

			ఒకవేళ (wild) {
				strstartseg = string;
				mismatch = నమూనా;

				/*
				 * Count fixed (non '*') char matches remaining
				 * in pattern * excluding '/' (or "\/") and '*'.
				 */
				కొరకు (matchptr = నమూనా, matchlen = 0; 1; ++matchlen) {
					ఒకవేళ ((*matchptr == '\0') ||
					    (slash && ((*matchptr == '/') ||
					    (escape && (*matchptr == '\\') &&
					    (matchptr[1] == '/'))))) {
						/* Compare precisely this many
						 * trailing string chars, the
						 * resulting match needs no
						 * wildcard loop.
						 */
						/* XXX: Adjust for MBCS */
						ఒకవేళ (string + matchlen > strendseg)
							తిరిగి FNM_NOMATCH;

						string = strendseg - matchlen;
						wild = 0;
						ఆపు;
					}

					ఒకవేళ (*matchptr == '*') {
						/*
						 * Ensure at least this many
						 * trailing string chars remain
						 * for the first comparison.
						 */
						/* XXX: Adjust for MBCS */
						ఒకవేళ (string + matchlen > strendseg)
							తిరిగి FNM_NOMATCH;

						/*
						 * Begin first wild comparison
						 * at the current position.
						 */
						ఆపు;
					}

					/*
					 * Skip forward in pattern by a single
					 * character match Use a dummy
					 * fnmatch_ch() test to count one
					 * "[range]" escape.
					 */
					/* XXX: Adjust for MBCS */
					ఒకవేళ (escape && (*matchptr == '\\') &&
					    matchptr[1]) {
						matchptr += 2;
					} లేకపోతే ఒకవేళ (*matchptr == '[') {
						dummyptr = dummystring;
						fnmatch_ch(&matchptr, &dummyptr,
						    flags);
					} లేకపోతే {
						++matchptr;
					}
				}
			}

			/* Incrementally match string against the pattern. */
			అయితే (*నమూనా && (string < strendseg)) {
				/* Success; begin a new wild pattern search. */
				ఒకవేళ (*నమూనా == '*')
					ఆపు;

				ఒకవేళ (slash && ((*string == '/') ||
				    (*నమూనా == '/') || (escape &&
				    (*నమూనా == '\\') && (నమూనా[1] == '/'))))
					ఆపు;

				/*
				 * Compare ch's (the pattern is advanced over
				 * "\/" to the '/', but slashes will mismatch,
				 * and are not consumed).
				 */
				ఒకవేళ (!fnmatch_ch(&నమూనా, &string, flags))
					కొనసాగు;

				/*
				 * Failed to match, loop against next char
				 * offset of string segment until not enough
				 * string chars remain to match the fixed
				 * pattern.
				 */
				ఒకవేళ (wild) {
					/* XXX: Advance 1 char for MBCS locale */
					string = ++strstartseg;
					ఒకవేళ (string + matchlen > strendseg)
						తిరిగి FNM_NOMATCH;

					నమూనా = mismatch;
					కొనసాగు;
				} లేకపోతే
					తిరిగి FNM_NOMATCH;
			}
		}

		ఒకవేళ (*string && !((slash || leading_dir) && (*string == '/')))
			తిరిగి FNM_NOMATCH;

		ఒకవేళ (*నమూనా && !(slash && ((*నమూనా == '/') ||
		    (escape && (*నమూనా == '\\') && (నమూనా[1] == '/')))))
			తిరిగి FNM_NOMATCH;

		ఒకవేళ (leading_dir && !*నమూనా && *string == '/')
			తిరిగి 0;
	}

	/* Where both pattern and string are at EOS, declare success.  */
	ఒకవేళ (!*string && !*నమూనా)
		తిరిగి 0;

	/* Pattern didn't match to the end of string. */
	తిరిగి FNM_NOMATCH;
}
#అయితే_ముగింపు /* HAVE_FNMATCH */
