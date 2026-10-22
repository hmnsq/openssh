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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
ସ୍ଥିର ଶୂନ୍ୟ
epsilon_closure(ଅକ୍ଷର *states, ଅଚଳ ଅକ୍ଷର *pattern, size_t M)
{
	size_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	ପାଇଁ (i = 0; i < M; i++) {
		ଯଦି (!states[i] || pattern[i] != '*')
			ଜାରି;
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_pattern(ଅଚଳ ଅକ୍ଷର *s, ଅଚଳ ଅକ୍ଷର *pattern)
{
	size_t M;
	size_t i;
	ଅକ୍ଷର *states, *next_states, *tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	ଯଦି ((M = strlen(pattern)) == 0)
		ଫେରନ୍ତୁ *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, ଆକାର(*states));
	next_states = xcalloc(M + 1, ଆକାର(*next_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	ପାଇଁ (; *s; s++) {
		memset(next_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		ପାଇଁ (i = 0; i < M; i++) {
			ଯଦି (!states[i])
				ଜାରି;
			ଯଦି (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				next_states[i] = 1;
			} ଅନ୍ୟଥା ଯଦି (pattern[i] == '?' || pattern[i] == *s) {
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
		ପାଇଁ (i = 0; i <= M; i++) {
			ଯଦି (states[i]) {
				active = 1;
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (!active)
			ଯାଅ out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	ମୁକ୍ତ(states);
	ମୁକ୍ତ(next_states);
	ଫେରନ୍ତୁ matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_pattern_list(ଅଚଳ ଅକ୍ଷର *string, ଅଚଳ ଅକ୍ଷର *pattern, ପୂର୍ଣ୍ଣସଂଖ୍ୟା dolower)
{
	ଅକ୍ଷର sub[1024];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା negated;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା got_positive;
	u_int i, subi, len = strlen(pattern);

	got_positive = 0;
	ପାଇଁ (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ଯଦି (pattern[i] == '!') {
			negated = 1;
			i++;
		} ଅନ୍ୟଥା
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		ପାଇଁ (subi = 0;
		    i < len && subi < ଆକାର(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)pattern[i]) ?
			    tolower((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		ଯଦି (subi >= ଆକାର(sub) - 1)
			ଫେରନ୍ତୁ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ଯଦି (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ଯଦି (match_pattern(string, sub)) {
			ଯଦି (negated)
				ଫେରନ୍ତୁ -1;		/* Negative */
			ଅନ୍ୟଥା
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ଫେରନ୍ତୁ got_positive;
}

/* Match a list representing users or groups. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_usergroup_pattern_list(ଅଚଳ ଅକ୍ଷର *string, ଅଚଳ ଅକ୍ଷର *pattern)
{
#ifdef HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	ଫେରନ୍ତୁ cygwin_ug_match_pattern_list(string, pattern);
#ଅନ୍ୟଥା
	/* Case sensitive match */
	ଫେରନ୍ତୁ match_pattern_list(string, pattern, 0);
#endif
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_hostname(ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *pattern)
{
	ଅକ୍ଷର *hostcopy = xstrdup(host);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	ମୁକ୍ତ(hostcopy);
	ଫେରନ୍ତୁ r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_host_and_ip(ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ipaddr,
    ଅଚଳ ଅକ୍ଷର *patterns)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା mhost, mip;

	ଯଦି ((mip = addr_match_list(ipaddr, patterns)) == -2)
		ଫେରନ୍ତୁ -1; /* error in ipaddr match */
	ଅନ୍ୟଥା ଯଦି (host == ଖାଲି || ipaddr == ଖାଲି || mip == -1)
		ଫେରନ୍ତୁ 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	ଯଦି ((mhost = match_hostname(host, patterns)) == -1)
		ଫେରନ୍ତୁ 0;
	/* no match at all */
	ଯଦି (mhost == 0 && mip == 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_user(ଅଚଳ ଅକ୍ଷର *user, ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ipaddr,
    ଅଚଳ ଅକ୍ଷର *pattern)
{
	ଅକ୍ଷର *p, *pat;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	/* test mode */
	ଯଦି (user == ଖାଲି && host == ଖାଲି && ipaddr == ଖାଲି) {
		ଯଦି ((p = strrchr(pattern, '@')) != ଖାଲି &&
		    match_host_and_ip(ଖାଲି, ଖାଲି, p + 1) < 0)
			ଫେରନ୍ତୁ -1;
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି (user == ଖାଲି)
		ଫେରନ୍ତୁ 0; /* shouldn't happen */

	ଯଦି (strrchr(pattern, '@') == ଖାଲି)
		ଫେରନ୍ତୁ match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = strrchr(pat, '@');
	*p++ = '\0';

	ଯଦି ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	ମୁକ୍ତ(pat);

	ଫେରନ୍ତୁ ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#define	MAX_PROP	40
#define	SEP	","
ଅକ୍ଷର *
match_list(ଅଚଳ ଅକ୍ଷର *client, ଅଚଳ ଅକ୍ଷର *server, u_int *next)
{
	ଅକ୍ଷର *sproposals[MAX_PROP];
	ଅକ୍ଷର *c, *s, *p, *ret, *cp, *sp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	ପାଇଁ ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		ଯଦି (i < MAX_PROP)
			sproposals[i] = p;
		ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
	}
	nproposals = i;

	ପାଇଁ ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		ପାଇଁ (j = 0; j < nproposals; j++) {
			ଯଦି (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				ଯଦି (next != ଖାଲି)
					*next = (cp == ଖାଲି) ?
					    strlen(c) : (u_int)(cp - c);
				ମୁକ୍ତ(c);
				ମୁକ୍ତ(s);
				ଫେରନ୍ତୁ ret;
			}
		}
	}
	ଯଦି (next != ଖାଲି)
		*next = strlen(c);
	ମୁକ୍ତ(c);
	ମୁକ୍ତ(s);
	ଫେରନ୍ତୁ ଖାଲି;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
ସ୍ଥିର ଅକ୍ଷର *
filter_list(ଅଚଳ ଅକ୍ଷର *proposal, ଅଚଳ ଅକ୍ଷର *filter, ପୂର୍ଣ୍ଣସଂଖ୍ୟା denylist)
{
	size_t len = strlen(proposal) + 1;
	ଅକ୍ଷର *fix_prop = malloc(len);
	ଅକ୍ଷର *orig_prop = strdup(proposal);
	ଅକ୍ଷର *cp, *tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (fix_prop == ଖାଲି || orig_prop == ଖାଲି) {
		ମୁକ୍ତ(orig_prop);
		ମୁକ୍ତ(fix_prop);
		ଫେରନ୍ତୁ ଖାଲି;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	ଯେତେବେଳେ ((cp = strsep(&tmp, ",")) != ଖାଲି) {
		r = match_pattern_list(cp, filter, 0);
		ଯଦି ((denylist && r != 1) || (!denylist && r == 1)) {
			ଯଦି (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	ମୁକ୍ତ(orig_prop);
	ଫେରନ୍ତୁ fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
ଅକ୍ଷର *
match_filter_denylist(ଅଚଳ ଅକ୍ଷର *proposal, ଅଚଳ ଅକ୍ଷର *filter)
{
	ଫେରନ୍ତୁ filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
ଅକ୍ଷର *
match_filter_allowlist(ଅଚଳ ଅକ୍ଷର *proposal, ଅଚଳ ଅକ୍ଷର *filter)
{
	ଫେରନ୍ତୁ filter_list(proposal, filter, 0);
}
