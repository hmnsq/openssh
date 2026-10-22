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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
સ્થિર શૂન્ય
epsilon_closure(અક્ષર *states, અચલ અક્ષર *pattern, size_t M)
{
	size_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	માટે (i = 0; i < M; i++) {
		જો (!states[i] || pattern[i] != '*')
			ચાલુ;
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
પૂર્ણાંક
match_pattern(અચલ અક્ષર *s, અચલ અક્ષર *pattern)
{
	size_t M;
	size_t i;
	અક્ષર *states, *next_states, *tmp;
	પૂર્ણાંક active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	જો ((M = strlen(pattern)) == 0)
		પાછા *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, કદ(*states));
	next_states = xcalloc(M + 1, કદ(*next_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	માટે (; *s; s++) {
		memset(next_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		માટે (i = 0; i < M; i++) {
			જો (!states[i])
				ચાલુ;
			જો (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				next_states[i] = 1;
			} નહીંતર જો (pattern[i] == '?' || pattern[i] == *s) {
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
		માટે (i = 0; i <= M; i++) {
			જો (states[i]) {
				active = 1;
				તોડો;
			}
		}
		જો (!active)
			જાઓ out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	મુક્ત(states);
	મુક્ત(next_states);
	પાછા matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
પૂર્ણાંક
match_pattern_list(અચલ અક્ષર *string, અચલ અક્ષર *pattern, પૂર્ણાંક dolower)
{
	અક્ષર sub[1024];
	પૂર્ણાંક negated;
	પૂર્ણાંક got_positive;
	u_int i, subi, len = strlen(pattern);

	got_positive = 0;
	માટે (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		જો (pattern[i] == '!') {
			negated = 1;
			i++;
		} નહીંતર
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		માટે (subi = 0;
		    i < len && subi < કદ(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)pattern[i]) ?
			    tolower((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		જો (subi >= કદ(sub) - 1)
			પાછા 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		જો (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		જો (match_pattern(string, sub)) {
			જો (negated)
				પાછા -1;		/* Negative */
			નહીંતર
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	પાછા got_positive;
}

/* Match a list representing users or groups. */
પૂર્ણાંક
match_usergroup_pattern_list(અચલ અક્ષર *string, અચલ અક્ષર *pattern)
{
#ifdef HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	પાછા cygwin_ug_match_pattern_list(string, pattern);
#નહીંતર
	/* Case sensitive match */
	પાછા match_pattern_list(string, pattern, 0);
#endif
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
પૂર્ણાંક
match_hostname(અચલ અક્ષર *host, અચલ અક્ષર *pattern)
{
	અક્ષર *hostcopy = xstrdup(host);
	પૂર્ણાંક r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	મુક્ત(hostcopy);
	પાછા r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
પૂર્ણાંક
match_host_and_ip(અચલ અક્ષર *host, અચલ અક્ષર *ipaddr,
    અચલ અક્ષર *patterns)
{
	પૂર્ણાંક mhost, mip;

	જો ((mip = addr_match_list(ipaddr, patterns)) == -2)
		પાછા -1; /* error in ipaddr match */
	નહીંતર જો (host == ખાલી || ipaddr == ખાલી || mip == -1)
		પાછા 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	જો ((mhost = match_hostname(host, patterns)) == -1)
		પાછા 0;
	/* no match at all */
	જો (mhost == 0 && mip == 0)
		પાછા 0;
	પાછા 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
પૂર્ણાંક
match_user(અચલ અક્ષર *user, અચલ અક્ષર *host, અચલ અક્ષર *ipaddr,
    અચલ અક્ષર *pattern)
{
	અક્ષર *p, *pat;
	પૂર્ણાંક ret;

	/* test mode */
	જો (user == ખાલી && host == ખાલી && ipaddr == ખાલી) {
		જો ((p = strrchr(pattern, '@')) != ખાલી &&
		    match_host_and_ip(ખાલી, ખાલી, p + 1) < 0)
			પાછા -1;
		પાછા 0;
	}

	જો (user == ખાલી)
		પાછા 0; /* shouldn't happen */

	જો (strrchr(pattern, '@') == ખાલી)
		પાછા match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = strrchr(pat, '@');
	*p++ = '\0';

	જો ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	મુક્ત(pat);

	પાછા ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#define	MAX_PROP	40
#define	SEP	","
અક્ષર *
match_list(અચલ અક્ષર *client, અચલ અક્ષર *server, u_int *next)
{
	અક્ષર *sproposals[MAX_PROP];
	અક્ષર *c, *s, *p, *ret, *cp, *sp;
	પૂર્ણાંક i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	માટે ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		જો (i < MAX_PROP)
			sproposals[i] = p;
		નહીંતર
			તોડો;
	}
	nproposals = i;

	માટે ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		માટે (j = 0; j < nproposals; j++) {
			જો (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				જો (next != ખાલી)
					*next = (cp == ખાલી) ?
					    strlen(c) : (u_int)(cp - c);
				મુક્ત(c);
				મુક્ત(s);
				પાછા ret;
			}
		}
	}
	જો (next != ખાલી)
		*next = strlen(c);
	મુક્ત(c);
	મુક્ત(s);
	પાછા ખાલી;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
સ્થિર અક્ષર *
filter_list(અચલ અક્ષર *proposal, અચલ અક્ષર *filter, પૂર્ણાંક denylist)
{
	size_t len = strlen(proposal) + 1;
	અક્ષર *fix_prop = malloc(len);
	અક્ષર *orig_prop = strdup(proposal);
	અક્ષર *cp, *tmp;
	પૂર્ણાંક r;

	જો (fix_prop == ખાલી || orig_prop == ખાલી) {
		મુક્ત(orig_prop);
		મુક્ત(fix_prop);
		પાછા ખાલી;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	જ્યારે ((cp = strsep(&tmp, ",")) != ખાલી) {
		r = match_pattern_list(cp, filter, 0);
		જો ((denylist && r != 1) || (!denylist && r == 1)) {
			જો (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	મુક્ત(orig_prop);
	પાછા fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
અક્ષર *
match_filter_denylist(અચલ અક્ષર *proposal, અચલ અક્ષર *filter)
{
	પાછા filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
અક્ષર *
match_filter_allowlist(અચલ અક્ષર *proposal, અચલ અક્ષર *filter)
{
	પાછા filter_list(proposal, filter, 0);
}
