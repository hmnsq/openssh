/* $OpenBSD: match.c,v 1.46 2026/05/31 04:19:16 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Simple pattern matching, with '*' and '?' as wildcards.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2026 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <ctype.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
স্থির শূন্য
epsilon_closure(ৱর্ণ *states, ধ্রুৱ ৱর্ণ *pattern, size_t M)
{
	size_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	বাবে (i = 0; i < M; i++) {
		যদি (!states[i] || pattern[i] != '*')
			অনুৱর্ত;
		/*
		 * State i is active, and pattern[i] is '*', so we can
		 * epsilon-transition to i+1.
		 */
		states[i + 1] = 1;
	}
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match. Uses an NFA internally.
 */
পূর্ণাঙ্ক
match_pattern(ধ্রুৱ ৱর্ণ *s, ধ্রুৱ ৱর্ণ *pattern)
{
	size_t M;
	size_t i;
	ৱর্ণ *states, *next_states, *tmp;
	পূর্ণাঙ্ক active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	যদি ((M = strlen(pattern)) == 0)
		ঘূৰাই *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, পরিমাণ(*states));
	next_states = xcalloc(M + 1, পরিমাণ(*next_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	বাবে (; *s; s++) {
		memset(next_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		বাবে (i = 0; i < M; i++) {
			যদি (!states[i])
				অনুৱর্ত;
			যদি (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				next_states[i] = 1;
			} অন্যথা যদি (pattern[i] == '?' || pattern[i] == *s) {
				/*
				 * '?' matches any character, or we have
				 * a literal match.
				 */
				next_states[i + 1] = 1;
			}
		}

		/* Expand the reachable next states with epsilon transitions */
		epsilon_closure(next_states, pattern, M);

		/* Swap states and next_states */
		tmp = states;
		states = next_states;
		next_states = tmp;

		/* Check if we have any active pattern states left */
		active = 0;
		বাবে (i = 0; i <= M; i++) {
			যদি (states[i]) {
				active = 1;
				ভঙ্গ;
			}
		}
		যদি (!active)
			গচ্ছ out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	মুক্ত(states);
	মুক্ত(next_states);
	ঘূৰাই matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
পূর্ণাঙ্ক
match_pattern_list(ধ্রুৱ ৱর্ণ *string, ধ্রুৱ ৱর্ণ *pattern, পূর্ণাঙ্ক dolower)
{
	ৱর্ণ sub[1024];
	পূর্ণাঙ্ক negated;
	পূর্ণাঙ্ক got_positive;
	u_int i, subi, len = strlen(pattern);

	got_positive = 0;
	বাবে (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		যদি (pattern[i] == '!') {
			negated = 1;
			i++;
		} অন্যথা
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		বাবে (subi = 0;
		    i < len && subi < পরিমাণ(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)pattern[i]) ?
			    tolower((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		যদি (subi >= পরিমাণ(sub) - 1)
			ঘূৰাই 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		যদি (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		যদি (match_pattern(string, sub)) {
			যদি (negated)
				ঘূৰাই -1;		/* Negative */
			অন্যথা
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ঘূৰাই got_positive;
}

/* Match a list representing users or groups. */
পূর্ণাঙ্ক
match_usergroup_pattern_list(ধ্রুৱ ৱর্ণ *string, ধ্রুৱ ৱর্ণ *pattern)
{
#ifdef HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	ঘূৰাই cygwin_ug_match_pattern_list(string, pattern);
#অন্যথা
	/* Case sensitive match */
	ঘূৰাই match_pattern_list(string, pattern, 0);
#endif
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
পূর্ণাঙ্ক
match_hostname(ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *pattern)
{
	ৱর্ণ *hostcopy = xstrdup(host);
	পূর্ণাঙ্ক r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	মুক্ত(hostcopy);
	ঘূৰাই r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
পূর্ণাঙ্ক
match_host_and_ip(ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *ipaddr,
    ধ্রুৱ ৱর্ণ *patterns)
{
	পূর্ণাঙ্ক mhost, mip;

	যদি ((mip = addr_match_list(ipaddr, patterns)) == -2)
		ঘূৰাই -1; /* error in ipaddr match */
	অন্যথা যদি (host == রিক্ত || ipaddr == রিক্ত || mip == -1)
		ঘূৰাই 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	যদি ((mhost = match_hostname(host, patterns)) == -1)
		ঘূৰাই 0;
	/* no match at all */
	যদি (mhost == 0 && mip == 0)
		ঘূৰাই 0;
	ঘূৰাই 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
পূর্ণাঙ্ক
match_user(ধ্রুৱ ৱর্ণ *user, ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *ipaddr,
    ধ্রুৱ ৱর্ণ *pattern)
{
	ৱর্ণ *p, *pat;
	পূর্ণাঙ্ক ret;

	/* test mode */
	যদি (user == রিক্ত && host == রিক্ত && ipaddr == রিক্ত) {
		যদি ((p = strrchr(pattern, '@')) != রিক্ত &&
		    match_host_and_ip(রিক্ত, রিক্ত, p + 1) < 0)
			ঘূৰাই -1;
		ঘূৰাই 0;
	}

	যদি (user == রিক্ত)
		ঘূৰাই 0; /* shouldn't happen */

	যদি (strrchr(pattern, '@') == রিক্ত)
		ঘূৰাই match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = strrchr(pat, '@');
	*p++ = '\0';

	যদি ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	মুক্ত(pat);

	ঘূৰাই ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#define	MAX_PROP	40
#define	SEP	","
ৱর্ণ *
match_list(ধ্রুৱ ৱর্ণ *client, ধ্রুৱ ৱর্ণ *server, u_int *next)
{
	ৱর্ণ *sproposals[MAX_PROP];
	ৱর্ণ *c, *s, *p, *ret, *cp, *sp;
	পূর্ণাঙ্ক i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	বাবে ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		যদি (i < MAX_PROP)
			sproposals[i] = p;
		অন্যথা
			ভঙ্গ;
	}
	nproposals = i;

	বাবে ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		বাবে (j = 0; j < nproposals; j++) {
			যদি (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				যদি (next != রিক্ত)
					*next = (cp == রিক্ত) ?
					    strlen(c) : (u_int)(cp - c);
				মুক্ত(c);
				মুক্ত(s);
				ঘূৰাই ret;
			}
		}
	}
	যদি (next != রিক্ত)
		*next = strlen(c);
	মুক্ত(c);
	মুক্ত(s);
	ঘূৰাই রিক্ত;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
স্থির ৱর্ণ *
filter_list(ধ্রুৱ ৱর্ণ *proposal, ধ্রুৱ ৱর্ণ *filter, পূর্ণাঙ্ক denylist)
{
	size_t len = strlen(proposal) + 1;
	ৱর্ণ *fix_prop = malloc(len);
	ৱর্ণ *orig_prop = strdup(proposal);
	ৱর্ণ *cp, *tmp;
	পূর্ণাঙ্ক r;

	যদি (fix_prop == রিক্ত || orig_prop == রিক্ত) {
		মুক্ত(orig_prop);
		মুক্ত(fix_prop);
		ঘূৰাই রিক্ত;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	যেতিয়ালৈ ((cp = strsep(&tmp, ",")) != রিক্ত) {
		r = match_pattern_list(cp, filter, 0);
		যদি ((denylist && r != 1) || (!denylist && r == 1)) {
			যদি (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	মুক্ত(orig_prop);
	ঘূৰাই fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
ৱর্ণ *
match_filter_denylist(ধ্রুৱ ৱর্ণ *proposal, ধ্রুৱ ৱর্ণ *filter)
{
	ঘূৰাই filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
ৱর্ণ *
match_filter_allowlist(ধ্রুৱ ৱর্ণ *proposal, ধ্রুৱ ৱর্ণ *filter)
{
	ঘূৰাই filter_list(proposal, filter, 0);
}
