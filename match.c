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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
ਸਥਿਰ ਖਾਲੀ
epsilon_ਘੇਰਾ(ਅੱਖਰ *ਹਾਲਤਾਂ, ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ, ਮਾਪ_t M)
{
	ਮਾਪ_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	ਲਈ (i = 0; i < M; i++) {
		ਜੇ (!ਹਾਲਤਾਂ[i] || ਨਮੂਨਾ[i] != '*')
			ਜਾਰੀ;
		/*
		 * State i is active, and pattern[i] is '*', so we can
		 * epsilon-transition to i+1.
		 */
		ਹਾਲਤਾਂ[i + 1] = 1;
	}
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match. Uses an NFA internally.
 */
ਪੂਰਨ
ਮੇਲ_ਨਮੂਨਾ(ਅਚਲ ਅੱਖਰ *s, ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ)
{
	ਮਾਪ_t M;
	ਮਾਪ_t i;
	ਅੱਖਰ *ਹਾਲਤਾਂ, *ਅਗਲਾ_ਹਾਲਤਾਂ, *tmp;
	ਪੂਰਨ ਸਰਗਰਮ, matched = 0;

	/* trivial case: empty pattern vs empty input */
	ਜੇ ((M = ਲੜੀ_ਲੰਬਾਈ(ਨਮੂਨਾ)) == 0)
		ਵਾਪਸ *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	ਹਾਲਤਾਂ = xcalloc(M + 1, ਆਕਾਰ(*ਹਾਲਤਾਂ));
	ਅਗਲਾ_ਹਾਲਤਾਂ = xcalloc(M + 1, ਆਕਾਰ(*ਅਗਲਾ_ਹਾਲਤਾਂ));

	/* Initial state: state 0 is active */
	ਹਾਲਤਾਂ[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_ਘੇਰਾ(ਹਾਲਤਾਂ, ਨਮੂਨਾ, M);

	ਲਈ (; *s; s++) {
		memset(ਅਗਲਾ_ਹਾਲਤਾਂ, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		ਲਈ (i = 0; i < M; i++) {
			ਜੇ (!ਹਾਲਤਾਂ[i])
				ਜਾਰੀ;
			ਜੇ (ਨਮੂਨਾ[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				ਅਗਲਾ_ਹਾਲਤਾਂ[i] = 1;
			} ਨਹੀਂਤਾਂ ਜੇ (ਨਮੂਨਾ[i] == '?' || ਨਮੂਨਾ[i] == *s) {
				/*
				 * '?' matches any character, or we have
				 * a literal match.
				 */
				ਅਗਲਾ_ਹਾਲਤਾਂ[i + 1] = 1;
			}
		}

		/* Expand the reachable next states with epsilon transitions */
		epsilon_ਘੇਰਾ(ਅਗਲਾ_ਹਾਲਤਾਂ, ਨਮੂਨਾ, M);

		/* Swap states and next_states */
		tmp = ਹਾਲਤਾਂ;
		ਹਾਲਤਾਂ = ਅਗਲਾ_ਹਾਲਤਾਂ;
		ਅਗਲਾ_ਹਾਲਤਾਂ = tmp;

		/* Check if we have any active pattern states left */
		ਸਰਗਰਮ = 0;
		ਲਈ (i = 0; i <= M; i++) {
			ਜੇ (ਹਾਲਤਾਂ[i]) {
				ਸਰਗਰਮ = 1;
				ਰੋਕੋ;
			}
		}
		ਜੇ (!ਸਰਗਰਮ)
			ਜਾਓ ਬਾਹਰਲਾ; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = ਹਾਲਤਾਂ[M];
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(ਹਾਲਤਾਂ);
	ਮੁਕਤ(ਅਗਲਾ_ਹਾਲਤਾਂ);
	ਵਾਪਸ matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ਪੂਰਨ
ਮੇਲ_ਨਮੂਨਾ_list(ਅਚਲ ਅੱਖਰ *string, ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ, ਪੂਰਨ dolower)
{
	ਅੱਖਰ sub[1024];
	ਪੂਰਨ negated;
	ਪੂਰਨ got_ਸਕਾਰਾਤਮਕ;
	u_int i, subi, len = ਲੜੀ_ਲੰਬਾਈ(ਨਮੂਨਾ);

	got_ਸਕਾਰਾਤਮਕ = 0;
	ਲਈ (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ਜੇ (ਨਮੂਨਾ[i] == '!') {
			negated = 1;
			i++;
		} ਨਹੀਂਤਾਂ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		ਲਈ (subi = 0;
		    i < len && subi < ਆਕਾਰ(sub) - 1 && ਨਮੂਨਾ[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)ਨਮੂਨਾ[i]) ?
			    tolower((u_char)ਨਮੂਨਾ[i]) : ਨਮੂਨਾ[i];
		/* If subpattern too long, return failure (no match). */
		ਜੇ (subi >= ਆਕਾਰ(sub) - 1)
			ਵਾਪਸ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ਜੇ (i < len && ਨਮੂਨਾ[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ(string, sub)) {
			ਜੇ (negated)
				ਵਾਪਸ -1;		/* Negative */
			ਨਹੀਂਤਾਂ
				got_ਸਕਾਰਾਤਮਕ = 1;	/*ਸਕਾਰਾਤਮਕ*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ਵਾਪਸ got_ਸਕਾਰਾਤਮਕ;
}

/* Match a list representing users or groups. */
ਪੂਰਨ
ਮੇਲ_usergroup_ਨਮੂਨਾ_list(ਅਚਲ ਅੱਖਰ *string, ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	ਵਾਪਸ cygwin_ug_ਮੇਲ_ਨਮੂਨਾ_list(string, ਨਮੂਨਾ);
#ਨਹੀਂਤਾਂ
	/* Case sensitive match */
	ਵਾਪਸ ਮੇਲ_ਨਮੂਨਾ_list(string, ਨਮੂਨਾ, 0);
#ਜੇ_ਅੰਤ
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ਪੂਰਨ
ਮੇਲ_hostname(ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ)
{
	ਅੱਖਰ *hostcopy = xstrdup(host);
	ਪੂਰਨ r;

	lowercase(hostcopy);
	r = ਮੇਲ_ਨਮੂਨਾ_list(hostcopy, ਨਮੂਨਾ, 1);
	ਮੁਕਤ(hostcopy);
	ਵਾਪਸ r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
ਪੂਰਨ
ਮੇਲ_host_and_ip(ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ipaddr,
    ਅਚਲ ਅੱਖਰ *patterns)
{
	ਪੂਰਨ mhost, mip;

	ਜੇ ((mip = addr_ਮੇਲ_list(ipaddr, patterns)) == -2)
		ਵਾਪਸ -1; /* error in ipaddr match */
	ਨਹੀਂਤਾਂ ਜੇ (host == ਨਿਰਾ || ipaddr == ਨਿਰਾ || mip == -1)
		ਵਾਪਸ 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	ਜੇ ((mhost = ਮੇਲ_hostname(host, patterns)) == -1)
		ਵਾਪਸ 0;
	/* no match at all */
	ਜੇ (mhost == 0 && mip == 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
ਪੂਰਨ
ਮੇਲ_user(ਅਚਲ ਅੱਖਰ *user, ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ipaddr,
    ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ)
{
	ਅੱਖਰ *p, *pat;
	ਪੂਰਨ ret;

	/* test mode */
	ਜੇ (user == ਨਿਰਾ && host == ਨਿਰਾ && ipaddr == ਨਿਰਾ) {
		ਜੇ ((p = strrchr(ਨਮੂਨਾ, '@')) != ਨਿਰਾ &&
		    ਮੇਲ_host_and_ip(ਨਿਰਾ, ਨਿਰਾ, p + 1) < 0)
			ਵਾਪਸ -1;
		ਵਾਪਸ 0;
	}

	ਜੇ (user == ਨਿਰਾ)
		ਵਾਪਸ 0; /* shouldn't happen */

	ਜੇ (strrchr(ਨਮੂਨਾ, '@') == ਨਿਰਾ)
		ਵਾਪਸ ਮੇਲ_ਨਮੂਨਾ(user, ਨਮੂਨਾ);

	pat = xstrdup(ਨਮੂਨਾ);
	p = strrchr(pat, '@');
	*p++ = '\0';

	ਜੇ ((ret = ਮੇਲ_ਨਮੂਨਾ(user, pat)) == 1)
		ret = ਮੇਲ_host_and_ip(host, ipaddr, p);
	ਮੁਕਤ(pat);

	ਵਾਪਸ ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	MAX_PROP	40
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SEP	","
ਅੱਖਰ *
ਮੇਲ_list(ਅਚਲ ਅੱਖਰ *client, ਅਚਲ ਅੱਖਰ *server, u_int *ਅਗਲਾ)
{
	ਅੱਖਰ *sproposals[MAX_PROP];
	ਅੱਖਰ *c, *s, *p, *ret, *cp, *sp;
	ਪੂਰਨ i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	ਲਈ ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		ਜੇ (i < MAX_PROP)
			sproposals[i] = p;
		ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
	}
	nproposals = i;

	ਲਈ ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		ਲਈ (j = 0; j < nproposals; j++) {
			ਜੇ (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				ਜੇ (ਅਗਲਾ != ਨਿਰਾ)
					*ਅਗਲਾ = (cp == ਨਿਰਾ) ?
					    ਲੜੀ_ਲੰਬਾਈ(c) : (u_int)(cp - c);
				ਮੁਕਤ(c);
				ਮੁਕਤ(s);
				ਵਾਪਸ ret;
			}
		}
	}
	ਜੇ (ਅਗਲਾ != ਨਿਰਾ)
		*ਅਗਲਾ = ਲੜੀ_ਲੰਬਾਈ(c);
	ਮੁਕਤ(c);
	ਮੁਕਤ(s);
	ਵਾਪਸ ਨਿਰਾ;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
ਸਥਿਰ ਅੱਖਰ *
filter_list(ਅਚਲ ਅੱਖਰ *proposal, ਅਚਲ ਅੱਖਰ *filter, ਪੂਰਨ denylist)
{
	ਮਾਪ_t len = ਲੜੀ_ਲੰਬਾਈ(proposal) + 1;
	ਅੱਖਰ *fix_prop = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len);
	ਅੱਖਰ *orig_prop = strdup(proposal);
	ਅੱਖਰ *cp, *tmp;
	ਪੂਰਨ r;

	ਜੇ (fix_prop == ਨਿਰਾ || orig_prop == ਨਿਰਾ) {
		ਮੁਕਤ(orig_prop);
		ਮੁਕਤ(fix_prop);
		ਵਾਪਸ ਨਿਰਾ;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	ਜਦੋਂ ((cp = strsep(&tmp, ",")) != ਨਿਰਾ) {
		r = ਮੇਲ_ਨਮੂਨਾ_list(cp, filter, 0);
		ਜੇ ((denylist && r != 1) || (!denylist && r == 1)) {
			ਜੇ (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	ਮੁਕਤ(orig_prop);
	ਵਾਪਸ fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
ਅੱਖਰ *
ਮੇਲ_filter_denylist(ਅਚਲ ਅੱਖਰ *proposal, ਅਚਲ ਅੱਖਰ *filter)
{
	ਵਾਪਸ filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
ਅੱਖਰ *
ਮੇਲ_filter_allowlist(ਅਚਲ ਅੱਖਰ *proposal, ਅਚਲ ਅੱਖਰ *filter)
{
	ਵਾਪਸ filter_list(proposal, filter, 0);
}
