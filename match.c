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
epsilon_ಆವರಣ(ಅಕ್ಷರ *ಸ್ಥಿತಿಗಳು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ, ಗಾತ್ರ_t M)
{
	ಗಾತ್ರ_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	ಗಾಗಿ (i = 0; i < M; i++) {
		ಆದರೆ (!ಸ್ಥಿತಿಗಳು[i] || ನಮೂನೆ[i] != '*')
			ಮುಂದುವರಿ;
		/*
		 * State i is active, and pattern[i] is '*', so we can
		 * epsilon-transition to i+1.
		 */
		ಸ್ಥಿತಿಗಳು[i + 1] = 1;
	}
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match. Uses an NFA internally.
 */
ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_ನಮೂನೆ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ)
{
	ಗಾತ್ರ_t M;
	ಗಾತ್ರ_t i;
	ಅಕ್ಷರ *ಸ್ಥಿತಿಗಳು, *ಮುಂದಿನ_ಸ್ಥಿತಿಗಳು, *tmp;
	ಪೂರ್ಣಾಂಕ ಸಕ್ರಿಯ, matched = 0;

	/* trivial case: empty pattern vs empty input */
	ಆದರೆ ((M = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ನಮೂನೆ)) == 0)
		ಹಿಂತಿರುಗಿ *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	ಸ್ಥಿತಿಗಳು = xcalloc(M + 1, ಗಾತ್ರ(*ಸ್ಥಿತಿಗಳು));
	ಮುಂದಿನ_ಸ್ಥಿತಿಗಳು = xcalloc(M + 1, ಗಾತ್ರ(*ಮುಂದಿನ_ಸ್ಥಿತಿಗಳು));

	/* Initial state: state 0 is active */
	ಸ್ಥಿತಿಗಳು[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_ಆವರಣ(ಸ್ಥಿತಿಗಳು, ನಮೂನೆ, M);

	ಗಾಗಿ (; *s; s++) {
		memset(ಮುಂದಿನ_ಸ್ಥಿತಿಗಳು, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		ಗಾಗಿ (i = 0; i < M; i++) {
			ಆದರೆ (!ಸ್ಥಿತಿಗಳು[i])
				ಮುಂದುವರಿ;
			ಆದರೆ (ನಮೂನೆ[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				ಮುಂದಿನ_ಸ್ಥಿತಿಗಳು[i] = 1;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ನಮೂನೆ[i] == '?' || ನಮೂನೆ[i] == *s) {
				/*
				 * '?' matches any character, or we have
				 * a literal match.
				 */
				ಮುಂದಿನ_ಸ್ಥಿತಿಗಳು[i + 1] = 1;
			}
		}

		/* Expand the reachable next states with epsilon transitions */
		epsilon_ಆವರಣ(ಮುಂದಿನ_ಸ್ಥಿತಿಗಳು, ನಮೂನೆ, M);

		/* Swap states and next_states */
		tmp = ಸ್ಥಿತಿಗಳು;
		ಸ್ಥಿತಿಗಳು = ಮುಂದಿನ_ಸ್ಥಿತಿಗಳು;
		ಮುಂದಿನ_ಸ್ಥಿತಿಗಳು = tmp;

		/* Check if we have any active pattern states left */
		ಸಕ್ರಿಯ = 0;
		ಗಾಗಿ (i = 0; i <= M; i++) {
			ಆದರೆ (ಸ್ಥಿತಿಗಳು[i]) {
				ಸಕ್ರಿಯ = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (!ಸಕ್ರಿಯ)
			ಹೋಗು ಹೊರಹೋಗು; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = ಸ್ಥಿತಿಗಳು[M];
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ಸ್ಥಿತಿಗಳು);
	ಬಿಡುಗಡೆ(ಮುಂದಿನ_ಸ್ಥಿತಿಗಳು);
	ಹಿಂತಿರುಗಿ matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *string, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ, ಪೂರ್ಣಾಂಕ dolower)
{
	ಅಕ್ಷರ sub[1024];
	ಪೂರ್ಣಾಂಕ negated;
	ಪೂರ್ಣಾಂಕ got_ಧನಾತ್ಮಕ;
	u_int i, subi, len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ನಮೂನೆ);

	got_ಧನಾತ್ಮಕ = 0;
	ಗಾಗಿ (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ಆದರೆ (ನಮೂನೆ[i] == '!') {
			negated = 1;
			i++;
		} ಇಲ್ಲದಿದ್ದರೆ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		ಗಾಗಿ (subi = 0;
		    i < len && subi < ಗಾತ್ರ(sub) - 1 && ನಮೂನೆ[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)ನಮೂನೆ[i]) ?
			    tolower((u_char)ನಮೂನೆ[i]) : ನಮೂನೆ[i];
		/* If subpattern too long, return failure (no match). */
		ಆದರೆ (subi >= ಗಾತ್ರ(sub) - 1)
			ಹಿಂತಿರುಗಿ 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ಆದರೆ (i < len && ನಮೂನೆ[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ(string, sub)) {
			ಆದರೆ (negated)
				ಹಿಂತಿರುಗಿ -1;		/* Negative */
			ಇಲ್ಲದಿದ್ದರೆ
				got_ಧನಾತ್ಮಕ = 1;	/*ಧನಾತ್ಮಕ*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ಹಿಂತಿರುಗಿ got_ಧನಾತ್ಮಕ;
}

/* Match a list representing users or groups. */
ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_usergroup_ನಮೂನೆ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *string, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	ಹಿಂತಿರುಗಿ cygwin_ug_ಹೊಂದಿಕೆ_ನಮೂನೆ_list(string, ನಮೂನೆ);
#ಇಲ್ಲದಿದ್ದರೆ
	/* Case sensitive match */
	ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_ನಮೂನೆ_list(string, ನಮೂನೆ, 0);
#ಆದರೆ_ಅಂತ್ಯ
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_hostname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ)
{
	ಅಕ್ಷರ *hostcopy = xstrdup(host);
	ಪೂರ್ಣಾಂಕ r;

	lowercase(hostcopy);
	r = ಹೊಂದಿಕೆ_ನಮೂನೆ_list(hostcopy, ನಮೂನೆ, 1);
	ಬಿಡುಗಡೆ(hostcopy);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_host_and_ip(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ipaddr,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *patterns)
{
	ಪೂರ್ಣಾಂಕ mhost, mip;

	ಆದರೆ ((mip = addr_ಹೊಂದಿಕೆ_list(ipaddr, patterns)) == -2)
		ಹಿಂತಿರುಗಿ -1; /* error in ipaddr match */
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (host == ಖಾಲಿ || ipaddr == ಖಾಲಿ || mip == -1)
		ಹಿಂತಿರುಗಿ 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	ಆದರೆ ((mhost = ಹೊಂದಿಕೆ_hostname(host, patterns)) == -1)
		ಹಿಂತಿರುಗಿ 0;
	/* no match at all */
	ಆದರೆ (mhost == 0 && mip == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_user(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ipaddr,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ)
{
	ಅಕ್ಷರ *p, *pat;
	ಪೂರ್ಣಾಂಕ ret;

	/* test mode */
	ಆದರೆ (user == ಖಾಲಿ && host == ಖಾಲಿ && ipaddr == ಖಾಲಿ) {
		ಆದರೆ ((p = strrchr(ನಮೂನೆ, '@')) != ಖಾಲಿ &&
		    ಹೊಂದಿಕೆ_host_and_ip(ಖಾಲಿ, ಖಾಲಿ, p + 1) < 0)
			ಹಿಂತಿರುಗಿ -1;
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ (user == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0; /* shouldn't happen */

	ಆದರೆ (strrchr(ನಮೂನೆ, '@') == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_ನಮೂನೆ(user, ನಮೂನೆ);

	pat = xstrdup(ನಮೂನೆ);
	p = strrchr(pat, '@');
	*p++ = '\0';

	ಆದರೆ ((ret = ಹೊಂದಿಕೆ_ನಮೂನೆ(user, pat)) == 1)
		ret = ಹೊಂದಿಕೆ_host_and_ip(host, ipaddr, p);
	ಬಿಡುಗಡೆ(pat);

	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	MAX_PROP	40
#ವ್ಯಾಖ್ಯಾನಿಸು	SEP	","
ಅಕ್ಷರ *
ಹೊಂದಿಕೆ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *client, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *server, u_int *ಮುಂದಿನ)
{
	ಅಕ್ಷರ *sproposals[MAX_PROP];
	ಅಕ್ಷರ *c, *s, *p, *ret, *cp, *sp;
	ಪೂರ್ಣಾಂಕ i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	ಗಾಗಿ ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		ಆದರೆ (i < MAX_PROP)
			sproposals[i] = p;
		ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
	}
	nproposals = i;

	ಗಾಗಿ ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		ಗಾಗಿ (j = 0; j < nproposals; j++) {
			ಆದರೆ (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				ಆದರೆ (ಮುಂದಿನ != ಖಾಲಿ)
					*ಮುಂದಿನ = (cp == ಖಾಲಿ) ?
					    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(c) : (u_int)(cp - c);
				ಬಿಡುಗಡೆ(c);
				ಬಿಡುಗಡೆ(s);
				ಹಿಂತಿರುಗಿ ret;
			}
		}
	}
	ಆದರೆ (ಮುಂದಿನ != ಖಾಲಿ)
		*ಮುಂದಿನ = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(c);
	ಬಿಡುಗಡೆ(c);
	ಬಿಡುಗಡೆ(s);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
filter_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proposal, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filter, ಪೂರ್ಣಾಂಕ denylist)
{
	ಗಾತ್ರ_t len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(proposal) + 1;
	ಅಕ್ಷರ *fix_prop = ಸ್ಮರಣೆ_ಕೊಡು(len);
	ಅಕ್ಷರ *orig_prop = strdup(proposal);
	ಅಕ್ಷರ *cp, *tmp;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (fix_prop == ಖಾಲಿ || orig_prop == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(orig_prop);
		ಬಿಡುಗಡೆ(fix_prop);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	ಆಗ ((cp = strsep(&tmp, ",")) != ಖಾಲಿ) {
		r = ಹೊಂದಿಕೆ_ನಮೂನೆ_list(cp, filter, 0);
		ಆದರೆ ((denylist && r != 1) || (!denylist && r == 1)) {
			ಆದರೆ (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	ಬಿಡುಗಡೆ(orig_prop);
	ಹಿಂತಿರುಗಿ fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
ಅಕ್ಷರ *
ಹೊಂದಿಕೆ_filter_denylist(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proposal, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filter)
{
	ಹಿಂತಿರುಗಿ filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
ಅಕ್ಷರ *
ಹೊಂದಿಕೆ_filter_allowlist(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proposal, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filter)
{
	ಹಿಂತಿರುಗಿ filter_list(proposal, filter, 0);
}
