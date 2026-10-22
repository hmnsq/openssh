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
epsilon_संवृतिः(वर्ण *अवस्थाः, ध्रुव वर्ण *आदर्शः, आकार_t M)
{
	आकार_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	प्रति (i = 0; i < M; i++) {
		यदि (!अवस्थाः[i] || आदर्शः[i] != '*')
			अनुवर्त;
		/*
		 * State i is active, and pattern[i] is '*', so we can
		 * epsilon-transition to i+1.
		 */
		अवस्थाः[i + 1] = 1;
	}
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match. Uses an NFA internally.
 */
पूर्णाङ्क
मेलनम्_आदर्शः(ध्रुव वर्ण *s, ध्रुव वर्ण *आदर्शः)
{
	आकार_t M;
	आकार_t i;
	वर्ण *अवस्थाः, *अग्र_अवस्थाः, *tmp;
	पूर्णाङ्क सक्रिय, matched = 0;

	/* trivial case: empty pattern vs empty input */
	यदि ((M = वाक्यदैर्घ्यम्(आदर्शः)) == 0)
		प्रत्यागम *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	अवस्थाः = xcalloc(M + 1, परिमाण(*अवस्थाः));
	अग्र_अवस्थाः = xcalloc(M + 1, परिमाण(*अग्र_अवस्थाः));

	/* Initial state: state 0 is active */
	अवस्थाः[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_संवृतिः(अवस्थाः, आदर्शः, M);

	प्रति (; *s; s++) {
		स्मृतिं_पूरय(अग्र_अवस्थाः, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		प्रति (i = 0; i < M; i++) {
			यदि (!अवस्थाः[i])
				अनुवर्त;
			यदि (आदर्शः[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				अग्र_अवस्थाः[i] = 1;
			} अन्यथा यदि (आदर्शः[i] == '?' || आदर्शः[i] == *s) {
				/*
				 * '?' matches any character, or we have
				 * a literal match.
				 */
				अग्र_अवस्थाः[i + 1] = 1;
			}
		}

		/* Expand the reachable next states with epsilon transitions */
		epsilon_संवृतिः(अग्र_अवस्थाः, आदर्शः, M);

		/* Swap states and next_states */
		tmp = अवस्थाः;
		अवस्थाः = अग्र_अवस्थाः;
		अग्र_अवस्थाः = tmp;

		/* Check if we have any active pattern states left */
		सक्रिय = 0;
		प्रति (i = 0; i <= M; i++) {
			यदि (अवस्थाः[i]) {
				सक्रिय = 1;
				भङ्ग;
			}
		}
		यदि (!सक्रिय)
			गच्छ बहिर्गमनम्; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = अवस्थाः[M];
 बहिर्गमनम्:
	मुक्त(अवस्थाः);
	मुक्त(अग्र_अवस्थाः);
	प्रत्यागम matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
पूर्णाङ्क
मेलनम्_आदर्शः_list(ध्रुव वर्ण *string, ध्रुव वर्ण *आदर्शः, पूर्णाङ्क dolower)
{
	वर्ण sub[1024];
	पूर्णाङ्क negated;
	पूर्णाङ्क got_धनात्मकम्;
	u_int i, subi, len = वाक्यदैर्घ्यम्(आदर्शः);

	got_धनात्मकम् = 0;
	प्रति (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		यदि (आदर्शः[i] == '!') {
			negated = 1;
			i++;
		} अन्यथा
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		प्रति (subi = 0;
		    i < len && subi < परिमाण(sub) - 1 && आदर्शः[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)आदर्शः[i]) ?
			    tolower((u_char)आदर्शः[i]) : आदर्शः[i];
		/* If subpattern too long, return failure (no match). */
		यदि (subi >= परिमाण(sub) - 1)
			प्रत्यागम 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		यदि (i < len && आदर्शः[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		यदि (मेलनम्_आदर्शः(string, sub)) {
			यदि (negated)
				प्रत्यागम -1;		/* Negative */
			अन्यथा
				got_धनात्मकम् = 1;	/*धनात्मकम्*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	प्रत्यागम got_धनात्मकम्;
}

/* Match a list representing users or groups. */
पूर्णाङ्क
मेलनम्_usergroup_आदर्शः_list(ध्रुव वर्ण *string, ध्रुव वर्ण *आदर्शः)
{
#यदि_परिभाषितम् HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	प्रत्यागम cygwin_ug_मेलनम्_आदर्शः_list(string, आदर्शः);
#अन्यथा
	/* Case sensitive match */
	प्रत्यागम मेलनम्_आदर्शः_list(string, आदर्शः, 0);
#यदि_अन्तः
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
पूर्णाङ्क
मेलनम्_hostname(ध्रुव वर्ण *host, ध्रुव वर्ण *आदर्शः)
{
	वर्ण *hostcopy = xstrdup(host);
	पूर्णाङ्क r;

	lowercase(hostcopy);
	r = मेलनम्_आदर्शः_list(hostcopy, आदर्शः, 1);
	मुक्त(hostcopy);
	प्रत्यागम r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
पूर्णाङ्क
मेलनम्_host_and_ip(ध्रुव वर्ण *host, ध्रुव वर्ण *ipaddr,
    ध्रुव वर्ण *patterns)
{
	पूर्णाङ्क mhost, mip;

	यदि ((mip = addr_मेलनम्_list(ipaddr, patterns)) == -2)
		प्रत्यागम -1; /* error in ipaddr match */
	अन्यथा यदि (host == रिक्त || ipaddr == रिक्त || mip == -1)
		प्रत्यागम 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	यदि ((mhost = मेलनम्_hostname(host, patterns)) == -1)
		प्रत्यागम 0;
	/* no match at all */
	यदि (mhost == 0 && mip == 0)
		प्रत्यागम 0;
	प्रत्यागम 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
पूर्णाङ्क
मेलनम्_user(ध्रुव वर्ण *user, ध्रुव वर्ण *host, ध्रुव वर्ण *ipaddr,
    ध्रुव वर्ण *आदर्शः)
{
	वर्ण *p, *pat;
	पूर्णाङ्क ret;

	/* test mode */
	यदि (user == रिक्त && host == रिक्त && ipaddr == रिक्त) {
		यदि ((p = strrchr(आदर्शः, '@')) != रिक्त &&
		    मेलनम्_host_and_ip(रिक्त, रिक्त, p + 1) < 0)
			प्रत्यागम -1;
		प्रत्यागम 0;
	}

	यदि (user == रिक्त)
		प्रत्यागम 0; /* shouldn't happen */

	यदि (strrchr(आदर्शः, '@') == रिक्त)
		प्रत्यागम मेलनम्_आदर्शः(user, आदर्शः);

	pat = xstrdup(आदर्शः);
	p = strrchr(pat, '@');
	*p++ = '\0';

	यदि ((ret = मेलनम्_आदर्शः(user, pat)) == 1)
		ret = मेलनम्_host_and_ip(host, ipaddr, p);
	मुक्त(pat);

	प्रत्यागम ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#परिभाषय	MAX_PROP	40
#परिभाषय	SEP	","
वर्ण *
मेलनम्_list(ध्रुव वर्ण *client, ध्रुव वर्ण *server, u_int *अग्र)
{
	वर्ण *sproposals[MAX_PROP];
	वर्ण *c, *s, *p, *ret, *cp, *sp;
	पूर्णाङ्क i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	प्रति ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		यदि (i < MAX_PROP)
			sproposals[i] = p;
		अन्यथा
			भङ्ग;
	}
	nproposals = i;

	प्रति ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		प्रति (j = 0; j < nproposals; j++) {
			यदि (वाक्यं_तुलय(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				यदि (अग्र != रिक्त)
					*अग्र = (cp == रिक्त) ?
					    वाक्यदैर्घ्यम्(c) : (u_int)(cp - c);
				मुक्त(c);
				मुक्त(s);
				प्रत्यागम ret;
			}
		}
	}
	यदि (अग्र != रिक्त)
		*अग्र = वाक्यदैर्घ्यम्(c);
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
	आकार_t len = वाक्यदैर्घ्यम्(proposal) + 1;
	वर्ण *fix_prop = स्मृतिं_देहि(len);
	वर्ण *orig_prop = strdup(proposal);
	वर्ण *cp, *tmp;
	पूर्णाङ्क r;

	यदि (fix_prop == रिक्त || orig_prop == रिक्त) {
		मुक्त(orig_prop);
		मुक्त(fix_prop);
		प्रत्यागम रिक्त;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	यावत् ((cp = strsep(&tmp, ",")) != रिक्त) {
		r = मेलनम्_आदर्शः_list(cp, filter, 0);
		यदि ((denylist && r != 1) || (!denylist && r == 1)) {
			यदि (*fix_prop != '\0')
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
मेलनम्_filter_denylist(ध्रुव वर्ण *proposal, ध्रुव वर्ण *filter)
{
	प्रत्यागम filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
वर्ण *
मेलनम्_filter_allowlist(ध्रुव वर्ण *proposal, ध्रुव वर्ण *filter)
{
	प्रत्यागम filter_list(proposal, filter, 0);
}
