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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
സ്ഥിതം ശൂന്യം
epsilon_closure(അക്ഷരം *states, സ്ഥിരം അക്ഷരം *pattern, size_t M)
{
	size_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	വേണ്ടി (i = 0; i < M; i++) {
		എങ്കിൽ (!states[i] || pattern[i] != '*')
			തുടരുക;
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
പൂർണ്ണസംഖ്യ
match_pattern(സ്ഥിരം അക്ഷരം *s, സ്ഥിരം അക്ഷരം *pattern)
{
	size_t M;
	size_t i;
	അക്ഷരം *states, *next_states, *tmp;
	പൂർണ്ണസംഖ്യ active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	എങ്കിൽ ((M = strlen(pattern)) == 0)
		തിരികെ *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, വലുപ്പം(*states));
	next_states = xcalloc(M + 1, വലുപ്പം(*next_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	വേണ്ടി (; *s; s++) {
		memset(next_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		വേണ്ടി (i = 0; i < M; i++) {
			എങ്കിൽ (!states[i])
				തുടരുക;
			എങ്കിൽ (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				next_states[i] = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (pattern[i] == '?' || pattern[i] == *s) {
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
		വേണ്ടി (i = 0; i <= M; i++) {
			എങ്കിൽ (states[i]) {
				active = 1;
				നിർത്തുക;
			}
		}
		എങ്കിൽ (!active)
			പോകുക out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	സ്വതന്ത്രം(states);
	സ്വതന്ത്രം(next_states);
	തിരികെ matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
പൂർണ്ണസംഖ്യ
match_pattern_list(സ്ഥിരം അക്ഷരം *string, സ്ഥിരം അക്ഷരം *pattern, പൂർണ്ണസംഖ്യ dolower)
{
	അക്ഷരം sub[1024];
	പൂർണ്ണസംഖ്യ negated;
	പൂർണ്ണസംഖ്യ got_positive;
	u_int i, subi, len = strlen(pattern);

	got_positive = 0;
	വേണ്ടി (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		എങ്കിൽ (pattern[i] == '!') {
			negated = 1;
			i++;
		} അല്ലെങ്കിൽ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		വേണ്ടി (subi = 0;
		    i < len && subi < വലുപ്പം(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)pattern[i]) ?
			    tolower((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		എങ്കിൽ (subi >= വലുപ്പം(sub) - 1)
			തിരികെ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		എങ്കിൽ (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		എങ്കിൽ (match_pattern(string, sub)) {
			എങ്കിൽ (negated)
				തിരികെ -1;		/* Negative */
			അല്ലെങ്കിൽ
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	തിരികെ got_positive;
}

/* Match a list representing users or groups. */
പൂർണ്ണസംഖ്യ
match_usergroup_pattern_list(സ്ഥിരം അക്ഷരം *string, സ്ഥിരം അക്ഷരം *pattern)
{
#ifdef HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	തിരികെ cygwin_ug_match_pattern_list(string, pattern);
#അല്ലെങ്കിൽ
	/* Case sensitive match */
	തിരികെ match_pattern_list(string, pattern, 0);
#endif
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
പൂർണ്ണസംഖ്യ
match_hostname(സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *pattern)
{
	അക്ഷരം *hostcopy = xstrdup(host);
	പൂർണ്ണസംഖ്യ r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	സ്വതന്ത്രം(hostcopy);
	തിരികെ r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
പൂർണ്ണസംഖ്യ
match_host_and_ip(സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ipaddr,
    സ്ഥിരം അക്ഷരം *patterns)
{
	പൂർണ്ണസംഖ്യ mhost, mip;

	എങ്കിൽ ((mip = addr_match_list(ipaddr, patterns)) == -2)
		തിരികെ -1; /* error in ipaddr match */
	അല്ലെങ്കിൽ എങ്കിൽ (host == ശൂന്യ || ipaddr == ശൂന്യ || mip == -1)
		തിരികെ 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	എങ്കിൽ ((mhost = match_hostname(host, patterns)) == -1)
		തിരികെ 0;
	/* no match at all */
	എങ്കിൽ (mhost == 0 && mip == 0)
		തിരികെ 0;
	തിരികെ 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
പൂർണ്ണസംഖ്യ
match_user(സ്ഥിരം അക്ഷരം *user, സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ipaddr,
    സ്ഥിരം അക്ഷരം *pattern)
{
	അക്ഷരം *p, *pat;
	പൂർണ്ണസംഖ്യ ret;

	/* test mode */
	എങ്കിൽ (user == ശൂന്യ && host == ശൂന്യ && ipaddr == ശൂന്യ) {
		എങ്കിൽ ((p = strrchr(pattern, '@')) != ശൂന്യ &&
		    match_host_and_ip(ശൂന്യ, ശൂന്യ, p + 1) < 0)
			തിരികെ -1;
		തിരികെ 0;
	}

	എങ്കിൽ (user == ശൂന്യ)
		തിരികെ 0; /* shouldn't happen */

	എങ്കിൽ (strrchr(pattern, '@') == ശൂന്യ)
		തിരികെ match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = strrchr(pat, '@');
	*p++ = '\0';

	എങ്കിൽ ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	സ്വതന്ത്രം(pat);

	തിരികെ ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#define	MAX_PROP	40
#define	SEP	","
അക്ഷരം *
match_list(സ്ഥിരം അക്ഷരം *client, സ്ഥിരം അക്ഷരം *server, u_int *next)
{
	അക്ഷരം *sproposals[MAX_PROP];
	അക്ഷരം *c, *s, *p, *ret, *cp, *sp;
	പൂർണ്ണസംഖ്യ i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	വേണ്ടി ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		എങ്കിൽ (i < MAX_PROP)
			sproposals[i] = p;
		അല്ലെങ്കിൽ
			നിർത്തുക;
	}
	nproposals = i;

	വേണ്ടി ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		വേണ്ടി (j = 0; j < nproposals; j++) {
			എങ്കിൽ (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				എങ്കിൽ (next != ശൂന്യ)
					*next = (cp == ശൂന്യ) ?
					    strlen(c) : (u_int)(cp - c);
				സ്വതന്ത്രം(c);
				സ്വതന്ത്രം(s);
				തിരികെ ret;
			}
		}
	}
	എങ്കിൽ (next != ശൂന്യ)
		*next = strlen(c);
	സ്വതന്ത്രം(c);
	സ്വതന്ത്രം(s);
	തിരികെ ശൂന്യ;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
സ്ഥിതം അക്ഷരം *
filter_list(സ്ഥിരം അക്ഷരം *proposal, സ്ഥിരം അക്ഷരം *filter, പൂർണ്ണസംഖ്യ denylist)
{
	size_t len = strlen(proposal) + 1;
	അക്ഷരം *fix_prop = malloc(len);
	അക്ഷരം *orig_prop = strdup(proposal);
	അക്ഷരം *cp, *tmp;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (fix_prop == ശൂന്യ || orig_prop == ശൂന്യ) {
		സ്വതന്ത്രം(orig_prop);
		സ്വതന്ത്രം(fix_prop);
		തിരികെ ശൂന്യ;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	ആകുമ്പോൾ ((cp = strsep(&tmp, ",")) != ശൂന്യ) {
		r = match_pattern_list(cp, filter, 0);
		എങ്കിൽ ((denylist && r != 1) || (!denylist && r == 1)) {
			എങ്കിൽ (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	സ്വതന്ത്രം(orig_prop);
	തിരികെ fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
അക്ഷരം *
match_filter_denylist(സ്ഥിരം അക്ഷരം *proposal, സ്ഥിരം അക്ഷരം *filter)
{
	തിരികെ filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
അക്ഷരം *
match_filter_allowlist(സ്ഥിരം അക്ഷരം *proposal, സ്ഥിരം അക്ഷരം *filter)
{
	തിരികെ filter_list(proposal, filter, 0);
}
