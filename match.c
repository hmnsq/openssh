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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
நிலையான வெறுமை
epsilon_closure(எழுத்து *states, மாறிலி எழுத்து *pattern, size_t M)
{
	size_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	க்கு (i = 0; i < M; i++) {
		எனில் (!states[i] || pattern[i] != '*')
			தொடர்;
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
முழு
match_pattern(மாறிலி எழுத்து *s, மாறிலி எழுத்து *pattern)
{
	size_t M;
	size_t i;
	எழுத்து *states, *next_states, *tmp;
	முழு active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	எனில் ((M = strlen(pattern)) == 0)
		திரும்பு *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, அளவு(*states));
	next_states = xcalloc(M + 1, அளவு(*next_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	க்கு (; *s; s++) {
		memset(next_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		க்கு (i = 0; i < M; i++) {
			எனில் (!states[i])
				தொடர்;
			எனில் (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				next_states[i] = 1;
			} இல்லையெனில் எனில் (pattern[i] == '?' || pattern[i] == *s) {
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
		க்கு (i = 0; i <= M; i++) {
			எனில் (states[i]) {
				active = 1;
				நிறுத்து;
			}
		}
		எனில் (!active)
			செல் out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	விடுவி(states);
	விடுவி(next_states);
	திரும்பு matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
முழு
match_pattern_list(மாறிலி எழுத்து *string, மாறிலி எழுத்து *pattern, முழு dolower)
{
	எழுத்து sub[1024];
	முழு negated;
	முழு got_positive;
	u_int i, subi, len = strlen(pattern);

	got_positive = 0;
	க்கு (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		எனில் (pattern[i] == '!') {
			negated = 1;
			i++;
		} இல்லையெனில்
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		க்கு (subi = 0;
		    i < len && subi < அளவு(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)pattern[i]) ?
			    tolower((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		எனில் (subi >= அளவு(sub) - 1)
			திரும்பு 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		எனில் (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		எனில் (match_pattern(string, sub)) {
			எனில் (negated)
				திரும்பு -1;		/* Negative */
			இல்லையெனில்
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	திரும்பு got_positive;
}

/* Match a list representing users or groups. */
முழு
match_usergroup_pattern_list(மாறிலி எழுத்து *string, மாறிலி எழுத்து *pattern)
{
#ifdef HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	திரும்பு cygwin_ug_match_pattern_list(string, pattern);
#இல்லையெனில்
	/* Case sensitive match */
	திரும்பு match_pattern_list(string, pattern, 0);
#endif
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
முழு
match_hostname(மாறிலி எழுத்து *host, மாறிலி எழுத்து *pattern)
{
	எழுத்து *hostcopy = xstrdup(host);
	முழு r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	விடுவி(hostcopy);
	திரும்பு r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
முழு
match_host_and_ip(மாறிலி எழுத்து *host, மாறிலி எழுத்து *ipaddr,
    மாறிலி எழுத்து *patterns)
{
	முழு mhost, mip;

	எனில் ((mip = addr_match_list(ipaddr, patterns)) == -2)
		திரும்பு -1; /* error in ipaddr match */
	இல்லையெனில் எனில் (host == வெற்று || ipaddr == வெற்று || mip == -1)
		திரும்பு 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	எனில் ((mhost = match_hostname(host, patterns)) == -1)
		திரும்பு 0;
	/* no match at all */
	எனில் (mhost == 0 && mip == 0)
		திரும்பு 0;
	திரும்பு 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
முழு
match_user(மாறிலி எழுத்து *user, மாறிலி எழுத்து *host, மாறிலி எழுத்து *ipaddr,
    மாறிலி எழுத்து *pattern)
{
	எழுத்து *p, *pat;
	முழு ret;

	/* test mode */
	எனில் (user == வெற்று && host == வெற்று && ipaddr == வெற்று) {
		எனில் ((p = strrchr(pattern, '@')) != வெற்று &&
		    match_host_and_ip(வெற்று, வெற்று, p + 1) < 0)
			திரும்பு -1;
		திரும்பு 0;
	}

	எனில் (user == வெற்று)
		திரும்பு 0; /* shouldn't happen */

	எனில் (strrchr(pattern, '@') == வெற்று)
		திரும்பு match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = strrchr(pat, '@');
	*p++ = '\0';

	எனில் ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	விடுவி(pat);

	திரும்பு ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#define	MAX_PROP	40
#define	SEP	","
எழுத்து *
match_list(மாறிலி எழுத்து *client, மாறிலி எழுத்து *server, u_int *next)
{
	எழுத்து *sproposals[MAX_PROP];
	எழுத்து *c, *s, *p, *ret, *cp, *sp;
	முழு i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	க்கு ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		எனில் (i < MAX_PROP)
			sproposals[i] = p;
		இல்லையெனில்
			நிறுத்து;
	}
	nproposals = i;

	க்கு ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		க்கு (j = 0; j < nproposals; j++) {
			எனில் (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				எனில் (next != வெற்று)
					*next = (cp == வெற்று) ?
					    strlen(c) : (u_int)(cp - c);
				விடுவி(c);
				விடுவி(s);
				திரும்பு ret;
			}
		}
	}
	எனில் (next != வெற்று)
		*next = strlen(c);
	விடுவி(c);
	விடுவி(s);
	திரும்பு வெற்று;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
நிலையான எழுத்து *
filter_list(மாறிலி எழுத்து *proposal, மாறிலி எழுத்து *filter, முழு denylist)
{
	size_t len = strlen(proposal) + 1;
	எழுத்து *fix_prop = malloc(len);
	எழுத்து *orig_prop = strdup(proposal);
	எழுத்து *cp, *tmp;
	முழு r;

	எனில் (fix_prop == வெற்று || orig_prop == வெற்று) {
		விடுவி(orig_prop);
		விடுவி(fix_prop);
		திரும்பு வெற்று;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	போது ((cp = strsep(&tmp, ",")) != வெற்று) {
		r = match_pattern_list(cp, filter, 0);
		எனில் ((denylist && r != 1) || (!denylist && r == 1)) {
			எனில் (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	விடுவி(orig_prop);
	திரும்பு fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
எழுத்து *
match_filter_denylist(மாறிலி எழுத்து *proposal, மாறிலி எழுத்து *filter)
{
	திரும்பு filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
எழுத்து *
match_filter_allowlist(மாறிலி எழுத்து *proposal, மாறிலி எழுத்து *filter)
{
	திரும்பு filter_list(proposal, filter, 0);
}
