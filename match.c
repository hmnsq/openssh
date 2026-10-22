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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
स्थिर शून्य
epsilon_closure(वर्ण *states, ध्रुव वर्ण *pattern, size_t M)
{
	size_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	प्रति (i = 0; i < M; i++) {
		जइ (!states[i] || pattern[i] != '*')
			अनुवर्त;
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
पूर्णाङ्क
match_pattern(ध्रुव वर्ण *s, ध्रुव वर्ण *pattern)
{
	size_t M;
	size_t i;
	वर्ण *states, *next_states, *tmp;
	पूर्णाङ्क active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	जइ ((M = strlen(pattern)) == 0)
		प्रत्यागम *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, परिमाण(*states));
	next_states = xcalloc(M + 1, परिमाण(*next_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	प्रति (; *s; s++) {
		memset(next_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		प्रति (i = 0; i < M; i++) {
			जइ (!states[i])
				अनुवर्त;
			जइ (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				next_states[i] = 1;
			} अण्णहा जइ (pattern[i] == '?' || pattern[i] == *s) {
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
		प्रति (i = 0; i <= M; i++) {
			जइ (states[i]) {
				active = 1;
				भङ्ग;
			}
		}
		जइ (!active)
			गच्छ out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	मुक्त(states);
	मुक्त(next_states);
	प्रत्यागम matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
पूर्णाङ्क
match_pattern_list(ध्रुव वर्ण *string, ध्रुव वर्ण *pattern, पूर्णाङ्क dolower)
{
	वर्ण sub[1024];
	पूर्णाङ्क negated;
	पूर्णाङ्क got_positive;
	u_int i, subi, len = strlen(pattern);

	got_positive = 0;
	प्रति (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		जइ (pattern[i] == '!') {
			negated = 1;
			i++;
		} अण्णहा
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		प्रति (subi = 0;
		    i < len && subi < परिमाण(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)pattern[i]) ?
			    tolower((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		जइ (subi >= परिमाण(sub) - 1)
			प्रत्यागम 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		जइ (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		जइ (match_pattern(string, sub)) {
			जइ (negated)
				प्रत्यागम -1;		/* Negative */
			अण्णहा
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	प्रत्यागम got_positive;
}

/* Match a list representing users or groups. */
पूर्णाङ्क
match_usergroup_pattern_list(ध्रुव वर्ण *string, ध्रुव वर्ण *pattern)
{
#ifdef HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	प्रत्यागम cygwin_ug_match_pattern_list(string, pattern);
#अण्णहा
	/* Case sensitive match */
	प्रत्यागम match_pattern_list(string, pattern, 0);
#endif
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
पूर्णाङ्क
match_hostname(ध्रुव वर्ण *host, ध्रुव वर्ण *pattern)
{
	वर्ण *hostcopy = xstrdup(host);
	पूर्णाङ्क r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	मुक्त(hostcopy);
	प्रत्यागम r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
पूर्णाङ्क
match_host_and_ip(ध्रुव वर्ण *host, ध्रुव वर्ण *ipaddr,
    ध्रुव वर्ण *patterns)
{
	पूर्णाङ्क mhost, mip;

	जइ ((mip = addr_match_list(ipaddr, patterns)) == -2)
		प्रत्यागम -1; /* error in ipaddr match */
	अण्णहा जइ (host == रिक्त || ipaddr == रिक्त || mip == -1)
		प्रत्यागम 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	जइ ((mhost = match_hostname(host, patterns)) == -1)
		प्रत्यागम 0;
	/* no match at all */
	जइ (mhost == 0 && mip == 0)
		प्रत्यागम 0;
	प्रत्यागम 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
पूर्णाङ्क
match_user(ध्रुव वर्ण *user, ध्रुव वर्ण *host, ध्रुव वर्ण *ipaddr,
    ध्रुव वर्ण *pattern)
{
	वर्ण *p, *pat;
	पूर्णाङ्क ret;

	/* test mode */
	जइ (user == रिक्त && host == रिक्त && ipaddr == रिक्त) {
		जइ ((p = strrchr(pattern, '@')) != रिक्त &&
		    match_host_and_ip(रिक्त, रिक्त, p + 1) < 0)
			प्रत्यागम -1;
		प्रत्यागम 0;
	}

	जइ (user == रिक्त)
		प्रत्यागम 0; /* shouldn't happen */

	जइ (strrchr(pattern, '@') == रिक्त)
		प्रत्यागम match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = strrchr(pat, '@');
	*p++ = '\0';

	जइ ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	मुक्त(pat);

	प्रत्यागम ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#define	MAX_PROP	40
#define	SEP	","
वर्ण *
match_list(ध्रुव वर्ण *client, ध्रुव वर्ण *server, u_int *next)
{
	वर्ण *sproposals[MAX_PROP];
	वर्ण *c, *s, *p, *ret, *cp, *sp;
	पूर्णाङ्क i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	प्रति ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		जइ (i < MAX_PROP)
			sproposals[i] = p;
		अण्णहा
			भङ्ग;
	}
	nproposals = i;

	प्रति ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		प्रति (j = 0; j < nproposals; j++) {
			जइ (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				जइ (next != रिक्त)
					*next = (cp == रिक्त) ?
					    strlen(c) : (u_int)(cp - c);
				मुक्त(c);
				मुक्त(s);
				प्रत्यागम ret;
			}
		}
	}
	जइ (next != रिक्त)
		*next = strlen(c);
	मुक्त(c);
	मुक्त(s);
	प्रत्यागम रिक्त;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
स्थिर वर्ण *
filter_list(ध्रुव वर्ण *proposal, ध्रुव वर्ण *filter, पूर्णाङ्क denylist)
{
	size_t len = strlen(proposal) + 1;
	वर्ण *fix_prop = malloc(len);
	वर्ण *orig_prop = strdup(proposal);
	वर्ण *cp, *tmp;
	पूर्णाङ्क r;

	जइ (fix_prop == रिक्त || orig_prop == रिक्त) {
		मुक्त(orig_prop);
		मुक्त(fix_prop);
		प्रत्यागम रिक्त;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	जाव ((cp = strsep(&tmp, ",")) != रिक्त) {
		r = match_pattern_list(cp, filter, 0);
		जइ ((denylist && r != 1) || (!denylist && r == 1)) {
			जइ (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	मुक्त(orig_prop);
	प्रत्यागम fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
वर्ण *
match_filter_denylist(ध्रुव वर्ण *proposal, ध्रुव वर्ण *filter)
{
	प्रत्यागम filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
वर्ण *
match_filter_allowlist(ध्रुव वर्ण *proposal, ध्रुव वर्ण *filter)
{
	प्रत्यागम filter_list(proposal, filter, 0);
}
