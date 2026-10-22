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

#include "includes.h"

#include <sys/types.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "xmalloc.h"
#include "match.h"
#include "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
static void
epsilon_closure(char *states, const char *pattern, size_t M)
{
	size_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	для (i = 0; i < M; i++) {
		якщо (!states[i] || pattern[i] != '*')
			continue;
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
ціле
match_pattern(const char *s, const char *pattern)
{
	size_t M;
	size_t i;
	char *states, *next_states, *tmp;
	ціле active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	якщо ((M = strlen(pattern)) == 0)
		повернути *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, sizeof(*states));
	next_states = xcalloc(M + 1, sizeof(*next_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	для (; *s; s++) {
		memset(next_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		для (i = 0; i < M; i++) {
			якщо (!states[i])
				continue;
			якщо (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				next_states[i] = 1;
			} інакше якщо (pattern[i] == '?' || pattern[i] == *s) {
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
		для (i = 0; i <= M; i++) {
			якщо (states[i]) {
				active = 1;
				break;
			}
		}
		якщо (!active)
			goto out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	free(states);
	free(next_states);
	повернути matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ціле
match_pattern_list(const char *string, const char *pattern, ціле dolower)
{
	char sub[1024];
	ціле negated;
	ціле got_positive;
	u_int i, subi, len = strlen(pattern);

	got_positive = 0;
	для (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		якщо (pattern[i] == '!') {
			negated = 1;
			i++;
		} інакше
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		для (subi = 0;
		    i < len && subi < sizeof(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)pattern[i]) ?
			    tolower((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		якщо (subi >= sizeof(sub) - 1)
			повернути 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		якщо (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		якщо (match_pattern(string, sub)) {
			якщо (negated)
				повернути -1;		/* Negative */
			інакше
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	повернути got_positive;
}

/* Match a list representing users or groups. */
ціле
match_usergroup_pattern_list(const char *string, const char *pattern)
{
#ifdef HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	повернути cygwin_ug_match_pattern_list(string, pattern);
#інакше
	/* Case sensitive match */
	повернути match_pattern_list(string, pattern, 0);
#endif
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ціле
match_hostname(const char *host, const char *pattern)
{
	char *hostcopy = xstrdup(host);
	ціле r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	free(hostcopy);
	повернути r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
ціле
match_host_and_ip(const char *host, const char *ipaddr,
    const char *patterns)
{
	ціле mhost, mip;

	якщо ((mip = addr_match_list(ipaddr, patterns)) == -2)
		повернути -1; /* error in ipaddr match */
	інакше якщо (host == NULL || ipaddr == NULL || mip == -1)
		повернути 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	якщо ((mhost = match_hostname(host, patterns)) == -1)
		повернути 0;
	/* no match at all */
	якщо (mhost == 0 && mip == 0)
		повернути 0;
	повернути 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
ціле
match_user(const char *user, const char *host, const char *ipaddr,
    const char *pattern)
{
	char *p, *pat;
	ціле ret;

	/* test mode */
	якщо (user == NULL && host == NULL && ipaddr == NULL) {
		якщо ((p = strrchr(pattern, '@')) != NULL &&
		    match_host_and_ip(NULL, NULL, p + 1) < 0)
			повернути -1;
		повернути 0;
	}

	якщо (user == NULL)
		повернути 0; /* shouldn't happen */

	якщо (strrchr(pattern, '@') == NULL)
		повернути match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = strrchr(pat, '@');
	*p++ = '\0';

	якщо ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	free(pat);

	повернути ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#define	MAX_PROP	40
#define	SEP	","
char *
match_list(const char *client, const char *server, u_int *next)
{
	char *sproposals[MAX_PROP];
	char *c, *s, *p, *ret, *cp, *sp;
	ціле i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	для ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		якщо (i < MAX_PROP)
			sproposals[i] = p;
		інакше
			break;
	}
	nproposals = i;

	для ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		для (j = 0; j < nproposals; j++) {
			якщо (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				якщо (next != NULL)
					*next = (cp == NULL) ?
					    strlen(c) : (u_int)(cp - c);
				free(c);
				free(s);
				повернути ret;
			}
		}
	}
	якщо (next != NULL)
		*next = strlen(c);
	free(c);
	free(s);
	повернути NULL;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
static char *
filter_list(const char *proposal, const char *filter, ціле denylist)
{
	size_t len = strlen(proposal) + 1;
	char *fix_prop = malloc(len);
	char *orig_prop = strdup(proposal);
	char *cp, *tmp;
	ціле r;

	якщо (fix_prop == NULL || orig_prop == NULL) {
		free(orig_prop);
		free(fix_prop);
		повернути NULL;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	поки ((cp = strsep(&tmp, ",")) != NULL) {
		r = match_pattern_list(cp, filter, 0);
		якщо ((denylist && r != 1) || (!denylist && r == 1)) {
			якщо (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	free(orig_prop);
	повернути fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
char *
match_filter_denylist(const char *proposal, const char *filter)
{
	повернути filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
char *
match_filter_allowlist(const char *proposal, const char *filter)
{
	повернути filter_list(proposal, filter, 0);
}
