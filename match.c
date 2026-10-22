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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <ctype.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <stdio.h>

#شامل "xmalloc.h"
#شامل "match.h"
#شامل "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
ایستا تهی
epsilon_closure(نویسه *states, ثابت نویسه *pattern, size_t M)
{
	size_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	برای (i = 0; i < M; i++) {
		اگر (!states[i] || pattern[i] != '*')
			ادامه;
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
صحیح
match_pattern(ثابت نویسه *s, ثابت نویسه *pattern)
{
	size_t M;
	size_t i;
	نویسه *states, *next_states, *tmp;
	صحیح active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	اگر ((M = strlen(pattern)) == 0)
		بازگشت *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, اندازه(*states));
	next_states = xcalloc(M + 1, اندازه(*next_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	برای (; *s; s++) {
		memset(next_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		برای (i = 0; i < M; i++) {
			اگر (!states[i])
				ادامه;
			اگر (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				next_states[i] = 1;
			} وگرنه اگر (pattern[i] == '?' || pattern[i] == *s) {
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
		برای (i = 0; i <= M; i++) {
			اگر (states[i]) {
				active = 1;
				بشکن;
			}
		}
		اگر (!active)
			برو out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	آزاد(states);
	آزاد(next_states);
	بازگشت matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
صحیح
match_pattern_list(ثابت نویسه *string, ثابت نویسه *pattern, صحیح dolower)
{
	نویسه sub[1024];
	صحیح negated;
	صحیح got_positive;
	u_int i, subi, len = strlen(pattern);

	got_positive = 0;
	برای (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		اگر (pattern[i] == '!') {
			negated = 1;
			i++;
		} وگرنه
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		برای (subi = 0;
		    i < len && subi < اندازه(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)pattern[i]) ?
			    tolower((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		اگر (subi >= اندازه(sub) - 1)
			بازگشت 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		اگر (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		اگر (match_pattern(string, sub)) {
			اگر (negated)
				بازگشت -1;		/* Negative */
			وگرنه
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	بازگشت got_positive;
}

/* Match a list representing users or groups. */
صحیح
match_usergroup_pattern_list(ثابت نویسه *string, ثابت نویسه *pattern)
{
#ifdef HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	بازگشت cygwin_ug_match_pattern_list(string, pattern);
#وگرنه
	/* Case sensitive match */
	بازگشت match_pattern_list(string, pattern, 0);
#endif
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
صحیح
match_hostname(ثابت نویسه *host, ثابت نویسه *pattern)
{
	نویسه *hostcopy = xstrdup(host);
	صحیح r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	آزاد(hostcopy);
	بازگشت r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
صحیح
match_host_and_ip(ثابت نویسه *host, ثابت نویسه *ipaddr,
    ثابت نویسه *patterns)
{
	صحیح mhost, mip;

	اگر ((mip = addr_match_list(ipaddr, patterns)) == -2)
		بازگشت -1; /* error in ipaddr match */
	وگرنه اگر (host == پوچ || ipaddr == پوچ || mip == -1)
		بازگشت 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	اگر ((mhost = match_hostname(host, patterns)) == -1)
		بازگشت 0;
	/* no match at all */
	اگر (mhost == 0 && mip == 0)
		بازگشت 0;
	بازگشت 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
صحیح
match_user(ثابت نویسه *user, ثابت نویسه *host, ثابت نویسه *ipaddr,
    ثابت نویسه *pattern)
{
	نویسه *p, *pat;
	صحیح ret;

	/* test mode */
	اگر (user == پوچ && host == پوچ && ipaddr == پوچ) {
		اگر ((p = strrchr(pattern, '@')) != پوچ &&
		    match_host_and_ip(پوچ, پوچ, p + 1) < 0)
			بازگشت -1;
		بازگشت 0;
	}

	اگر (user == پوچ)
		بازگشت 0; /* shouldn't happen */

	اگر (strrchr(pattern, '@') == پوچ)
		بازگشت match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = strrchr(pat, '@');
	*p++ = '\0';

	اگر ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	آزاد(pat);

	بازگشت ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#define	MAX_PROP	40
#define	SEP	","
نویسه *
match_list(ثابت نویسه *client, ثابت نویسه *server, u_int *next)
{
	نویسه *sproposals[MAX_PROP];
	نویسه *c, *s, *p, *ret, *cp, *sp;
	صحیح i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	برای ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		اگر (i < MAX_PROP)
			sproposals[i] = p;
		وگرنه
			بشکن;
	}
	nproposals = i;

	برای ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		برای (j = 0; j < nproposals; j++) {
			اگر (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				اگر (next != پوچ)
					*next = (cp == پوچ) ?
					    strlen(c) : (u_int)(cp - c);
				آزاد(c);
				آزاد(s);
				بازگشت ret;
			}
		}
	}
	اگر (next != پوچ)
		*next = strlen(c);
	آزاد(c);
	آزاد(s);
	بازگشت پوچ;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
ایستا نویسه *
filter_list(ثابت نویسه *proposal, ثابت نویسه *filter, صحیح denylist)
{
	size_t len = strlen(proposal) + 1;
	نویسه *fix_prop = malloc(len);
	نویسه *orig_prop = strdup(proposal);
	نویسه *cp, *tmp;
	صحیح r;

	اگر (fix_prop == پوچ || orig_prop == پوچ) {
		آزاد(orig_prop);
		آزاد(fix_prop);
		بازگشت پوچ;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	وقتی ((cp = strsep(&tmp, ",")) != پوچ) {
		r = match_pattern_list(cp, filter, 0);
		اگر ((denylist && r != 1) || (!denylist && r == 1)) {
			اگر (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	آزاد(orig_prop);
	بازگشت fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
نویسه *
match_filter_denylist(ثابت نویسه *proposal, ثابت نویسه *filter)
{
	بازگشت filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
نویسه *
match_filter_allowlist(ثابت نویسه *proposal, ثابت نویسه *filter)
{
	بازگشت filter_list(proposal, filter, 0);
}
