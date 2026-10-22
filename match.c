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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
epsilon_closure(ವರ್ಣ *states, ಧ್ರುವ ವರ್ಣ *pattern, size_t M)
{
	size_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	ಪ್ರತಿ (i = 0; i < M; i++) {
		ಯದಿ (!states[i] || pattern[i] != '*')
			ಅನುವರ್ತ;
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
ಪೂರ್ಣಾಙ್ಕ
match_pattern(ಧ್ರುವ ವರ್ಣ *s, ಧ್ರುವ ವರ್ಣ *pattern)
{
	size_t M;
	size_t i;
	ವರ್ಣ *states, *next_states, *tmp;
	ಪೂರ್ಣಾಙ್ಕ active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	ಯದಿ ((M = strlen(pattern)) == 0)
		ಪ್ರತ್ಯಾಗಮ *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, ಪರಿಮಾಣ(*states));
	next_states = xcalloc(M + 1, ಪರಿಮಾಣ(*next_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	ಪ್ರತಿ (; *s; s++) {
		memset(next_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		ಪ್ರತಿ (i = 0; i < M; i++) {
			ಯದಿ (!states[i])
				ಅನುವರ್ತ;
			ಯದಿ (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				next_states[i] = 1;
			} ಅನ್ಯಥಾ ಯದಿ (pattern[i] == '?' || pattern[i] == *s) {
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
		ಪ್ರತಿ (i = 0; i <= M; i++) {
			ಯದಿ (states[i]) {
				active = 1;
				ಭಙ್ಗ;
			}
		}
		ಯದಿ (!active)
			ಗಚ್ಛ out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	ಮುಕ್ತ(states);
	ಮುಕ್ತ(next_states);
	ಪ್ರತ್ಯಾಗಮ matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ಪೂರ್ಣಾಙ್ಕ
match_pattern_list(ಧ್ರುವ ವರ್ಣ *string, ಧ್ರುವ ವರ್ಣ *pattern, ಪೂರ್ಣಾಙ್ಕ dolower)
{
	ವರ್ಣ sub[1024];
	ಪೂರ್ಣಾಙ್ಕ negated;
	ಪೂರ್ಣಾಙ್ಕ got_positive;
	u_int i, subi, len = strlen(pattern);

	got_positive = 0;
	ಪ್ರತಿ (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ಯದಿ (pattern[i] == '!') {
			negated = 1;
			i++;
		} ಅನ್ಯಥಾ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		ಪ್ರತಿ (subi = 0;
		    i < len && subi < ಪರಿಮಾಣ(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)pattern[i]) ?
			    tolower((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		ಯದಿ (subi >= ಪರಿಮಾಣ(sub) - 1)
			ಪ್ರತ್ಯಾಗಮ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ಯದಿ (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ಯದಿ (match_pattern(string, sub)) {
			ಯದಿ (negated)
				ಪ್ರತ್ಯಾಗಮ -1;		/* Negative */
			ಅನ್ಯಥಾ
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ಪ್ರತ್ಯಾಗಮ got_positive;
}

/* Match a list representing users or groups. */
ಪೂರ್ಣಾಙ್ಕ
match_usergroup_pattern_list(ಧ್ರುವ ವರ್ಣ *string, ಧ್ರುವ ವರ್ಣ *pattern)
{
#ifdef HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	ಪ್ರತ್ಯಾಗಮ cygwin_ug_match_pattern_list(string, pattern);
#ಅನ್ಯಥಾ
	/* Case sensitive match */
	ಪ್ರತ್ಯಾಗಮ match_pattern_list(string, pattern, 0);
#endif
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ಪೂರ್ಣಾಙ್ಕ
match_hostname(ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *pattern)
{
	ವರ್ಣ *hostcopy = xstrdup(host);
	ಪೂರ್ಣಾಙ್ಕ r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	ಮುಕ್ತ(hostcopy);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
ಪೂರ್ಣಾಙ್ಕ
match_host_and_ip(ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ipaddr,
    ಧ್ರುವ ವರ್ಣ *patterns)
{
	ಪೂರ್ಣಾಙ್ಕ mhost, mip;

	ಯದಿ ((mip = addr_match_list(ipaddr, patterns)) == -2)
		ಪ್ರತ್ಯಾಗಮ -1; /* error in ipaddr match */
	ಅನ್ಯಥಾ ಯದಿ (host == ರಿಕ್ತ || ipaddr == ರಿಕ್ತ || mip == -1)
		ಪ್ರತ್ಯಾಗಮ 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	ಯದಿ ((mhost = match_hostname(host, patterns)) == -1)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* no match at all */
	ಯದಿ (mhost == 0 && mip == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
ಪೂರ್ಣಾಙ್ಕ
match_user(ಧ್ರುವ ವರ್ಣ *user, ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ipaddr,
    ಧ್ರುವ ವರ್ಣ *pattern)
{
	ವರ್ಣ *p, *pat;
	ಪೂರ್ಣಾಙ್ಕ ret;

	/* test mode */
	ಯದಿ (user == ರಿಕ್ತ && host == ರಿಕ್ತ && ipaddr == ರಿಕ್ತ) {
		ಯದಿ ((p = strrchr(pattern, '@')) != ರಿಕ್ತ &&
		    match_host_and_ip(ರಿಕ್ತ, ರಿಕ್ತ, p + 1) < 0)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ (user == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0; /* shouldn't happen */

	ಯದಿ (strrchr(pattern, '@') == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = strrchr(pat, '@');
	*p++ = '\0';

	ಯದಿ ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	ಮುಕ್ತ(pat);

	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#define	MAX_PROP	40
#define	SEP	","
ವರ್ಣ *
match_list(ಧ್ರುವ ವರ್ಣ *client, ಧ್ರುವ ವರ್ಣ *server, u_int *next)
{
	ವರ್ಣ *sproposals[MAX_PROP];
	ವರ್ಣ *c, *s, *p, *ret, *cp, *sp;
	ಪೂರ್ಣಾಙ್ಕ i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	ಪ್ರತಿ ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		ಯದಿ (i < MAX_PROP)
			sproposals[i] = p;
		ಅನ್ಯಥಾ
			ಭಙ್ಗ;
	}
	nproposals = i;

	ಪ್ರತಿ ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		ಪ್ರತಿ (j = 0; j < nproposals; j++) {
			ಯದಿ (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				ಯದಿ (next != ರಿಕ್ತ)
					*next = (cp == ರಿಕ್ತ) ?
					    strlen(c) : (u_int)(cp - c);
				ಮುಕ್ತ(c);
				ಮುಕ್ತ(s);
				ಪ್ರತ್ಯಾಗಮ ret;
			}
		}
	}
	ಯದಿ (next != ರಿಕ್ತ)
		*next = strlen(c);
	ಮುಕ್ತ(c);
	ಮುಕ್ತ(s);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
ಸ್ಥಿರ ವರ್ಣ *
filter_list(ಧ್ರುವ ವರ್ಣ *proposal, ಧ್ರುವ ವರ್ಣ *filter, ಪೂರ್ಣಾಙ್ಕ denylist)
{
	size_t len = strlen(proposal) + 1;
	ವರ್ಣ *fix_prop = malloc(len);
	ವರ್ಣ *orig_prop = strdup(proposal);
	ವರ್ಣ *cp, *tmp;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (fix_prop == ರಿಕ್ತ || orig_prop == ರಿಕ್ತ) {
		ಮುಕ್ತ(orig_prop);
		ಮುಕ್ತ(fix_prop);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	ಯಾವತ್ ((cp = strsep(&tmp, ",")) != ರಿಕ್ತ) {
		r = match_pattern_list(cp, filter, 0);
		ಯದಿ ((denylist && r != 1) || (!denylist && r == 1)) {
			ಯದಿ (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	ಮುಕ್ತ(orig_prop);
	ಪ್ರತ್ಯಾಗಮ fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
ವರ್ಣ *
match_filter_denylist(ಧ್ರುವ ವರ್ಣ *proposal, ಧ್ರುವ ವರ್ಣ *filter)
{
	ಪ್ರತ್ಯಾಗಮ filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
ವರ್ಣ *
match_filter_allowlist(ಧ್ರುವ ವರ್ಣ *proposal, ಧ್ರುವ ವರ್ಣ *filter)
{
	ಪ್ರತ್ಯಾಗಮ filter_list(proposal, filter, 0);
}
