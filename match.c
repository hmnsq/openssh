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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
స్థిర శూన్య
epsilon_సంవృతం(అక్షరం *స్థితులు, స్థిరరాశి అక్షరం *నమూనా, కొలత_t M)
{
	కొలత_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	కొరకు (i = 0; i < M; i++) {
		ఒకవేళ (!స్థితులు[i] || నమూనా[i] != '*')
			కొనసాగు;
		/*
		 * State i is active, and pattern[i] is '*', so we can
		 * epsilon-transition to i+1.
		 */
		స్థితులు[i + 1] = 1;
	}
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match. Uses an NFA internally.
 */
పూర్ణాంకం
సరిపోలిక_నమూనా(స్థిరరాశి అక్షరం *s, స్థిరరాశి అక్షరం *నమూనా)
{
	కొలత_t M;
	కొలత_t i;
	అక్షరం *స్థితులు, *తదుపరి_స్థితులు, *tmp;
	పూర్ణాంకం చురుకైన, matched = 0;

	/* trivial case: empty pattern vs empty input */
	ఒకవేళ ((M = అక్షరశ్రేణి_పొడవు(నమూనా)) == 0)
		తిరిగి *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	స్థితులు = xcalloc(M + 1, పరిమాణం(*స్థితులు));
	తదుపరి_స్థితులు = xcalloc(M + 1, పరిమాణం(*తదుపరి_స్థితులు));

	/* Initial state: state 0 is active */
	స్థితులు[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_సంవృతం(స్థితులు, నమూనా, M);

	కొరకు (; *s; s++) {
		memset(తదుపరి_స్థితులు, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		కొరకు (i = 0; i < M; i++) {
			ఒకవేళ (!స్థితులు[i])
				కొనసాగు;
			ఒకవేళ (నమూనా[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				తదుపరి_స్థితులు[i] = 1;
			} లేకపోతే ఒకవేళ (నమూనా[i] == '?' || నమూనా[i] == *s) {
				/*
				 * '?' matches any character, or we have
				 * a literal match.
				 */
				తదుపరి_స్థితులు[i + 1] = 1;
			}
		}

		/* Expand the reachable next states with epsilon transitions */
		epsilon_సంవృతం(తదుపరి_స్థితులు, నమూనా, M);

		/* Swap states and next_states */
		tmp = స్థితులు;
		స్థితులు = తదుపరి_స్థితులు;
		తదుపరి_స్థితులు = tmp;

		/* Check if we have any active pattern states left */
		చురుకైన = 0;
		కొరకు (i = 0; i <= M; i++) {
			ఒకవేళ (స్థితులు[i]) {
				చురుకైన = 1;
				ఆపు;
			}
		}
		ఒకవేళ (!చురుకైన)
			వెళ్ళు బహిర్గతం; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = స్థితులు[M];
 బహిర్గతం:
	విడుదల(స్థితులు);
	విడుదల(తదుపరి_స్థితులు);
	తిరిగి matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
పూర్ణాంకం
సరిపోలిక_నమూనా_list(స్థిరరాశి అక్షరం *string, స్థిరరాశి అక్షరం *నమూనా, పూర్ణాంకం dolower)
{
	అక్షరం sub[1024];
	పూర్ణాంకం negated;
	పూర్ణాంకం got_ధనాత్మక;
	u_int i, subi, len = అక్షరశ్రేణి_పొడవు(నమూనా);

	got_ధనాత్మక = 0;
	కొరకు (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		ఒకవేళ (నమూనా[i] == '!') {
			negated = 1;
			i++;
		} లేకపోతే
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		కొరకు (subi = 0;
		    i < len && subi < పరిమాణం(sub) - 1 && నమూనా[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)నమూనా[i]) ?
			    tolower((u_char)నమూనా[i]) : నమూనా[i];
		/* If subpattern too long, return failure (no match). */
		ఒకవేళ (subi >= పరిమాణం(sub) - 1)
			తిరిగి 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		ఒకవేళ (i < len && నమూనా[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		ఒకవేళ (సరిపోలిక_నమూనా(string, sub)) {
			ఒకవేళ (negated)
				తిరిగి -1;		/* Negative */
			లేకపోతే
				got_ధనాత్మక = 1;	/*ధనాత్మక*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	తిరిగి got_ధనాత్మక;
}

/* Match a list representing users or groups. */
పూర్ణాంకం
సరిపోలిక_usergroup_నమూనా_list(స్థిరరాశి అక్షరం *string, స్థిరరాశి అక్షరం *నమూనా)
{
#నిర్వచితమైతే HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	తిరిగి cygwin_ug_సరిపోలిక_నమూనా_list(string, నమూనా);
#లేకపోతే
	/* Case sensitive match */
	తిరిగి సరిపోలిక_నమూనా_list(string, నమూనా, 0);
#అయితే_ముగింపు
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
పూర్ణాంకం
సరిపోలిక_hostname(స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *నమూనా)
{
	అక్షరం *hostcopy = xstrdup(host);
	పూర్ణాంకం r;

	lowercase(hostcopy);
	r = సరిపోలిక_నమూనా_list(hostcopy, నమూనా, 1);
	విడుదల(hostcopy);
	తిరిగి r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
పూర్ణాంకం
సరిపోలిక_host_and_ip(స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ipaddr,
    స్థిరరాశి అక్షరం *patterns)
{
	పూర్ణాంకం mhost, mip;

	ఒకవేళ ((mip = addr_సరిపోలిక_list(ipaddr, patterns)) == -2)
		తిరిగి -1; /* error in ipaddr match */
	లేకపోతే ఒకవేళ (host == ఖాళీ || ipaddr == ఖాళీ || mip == -1)
		తిరిగి 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	ఒకవేళ ((mhost = సరిపోలిక_hostname(host, patterns)) == -1)
		తిరిగి 0;
	/* no match at all */
	ఒకవేళ (mhost == 0 && mip == 0)
		తిరిగి 0;
	తిరిగి 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
పూర్ణాంకం
సరిపోలిక_user(స్థిరరాశి అక్షరం *user, స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ipaddr,
    స్థిరరాశి అక్షరం *నమూనా)
{
	అక్షరం *p, *pat;
	పూర్ణాంకం ret;

	/* test mode */
	ఒకవేళ (user == ఖాళీ && host == ఖాళీ && ipaddr == ఖాళీ) {
		ఒకవేళ ((p = strrchr(నమూనా, '@')) != ఖాళీ &&
		    సరిపోలిక_host_and_ip(ఖాళీ, ఖాళీ, p + 1) < 0)
			తిరిగి -1;
		తిరిగి 0;
	}

	ఒకవేళ (user == ఖాళీ)
		తిరిగి 0; /* shouldn't happen */

	ఒకవేళ (strrchr(నమూనా, '@') == ఖాళీ)
		తిరిగి సరిపోలిక_నమూనా(user, నమూనా);

	pat = xstrdup(నమూనా);
	p = strrchr(pat, '@');
	*p++ = '\0';

	ఒకవేళ ((ret = సరిపోలిక_నమూనా(user, pat)) == 1)
		ret = సరిపోలిక_host_and_ip(host, ipaddr, p);
	విడుదల(pat);

	తిరిగి ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#నిర్వచించు	MAX_PROP	40
#నిర్వచించు	SEP	","
అక్షరం *
సరిపోలిక_list(స్థిరరాశి అక్షరం *client, స్థిరరాశి అక్షరం *server, u_int *తదుపరి)
{
	అక్షరం *sproposals[MAX_PROP];
	అక్షరం *c, *s, *p, *ret, *cp, *sp;
	పూర్ణాంకం i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	కొరకు ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		ఒకవేళ (i < MAX_PROP)
			sproposals[i] = p;
		లేకపోతే
			ఆపు;
	}
	nproposals = i;

	కొరకు ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		కొరకు (j = 0; j < nproposals; j++) {
			ఒకవేళ (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				ఒకవేళ (తదుపరి != ఖాళీ)
					*తదుపరి = (cp == ఖాళీ) ?
					    అక్షరశ్రేణి_పొడవు(c) : (u_int)(cp - c);
				విడుదల(c);
				విడుదల(s);
				తిరిగి ret;
			}
		}
	}
	ఒకవేళ (తదుపరి != ఖాళీ)
		*తదుపరి = అక్షరశ్రేణి_పొడవు(c);
	విడుదల(c);
	విడుదల(s);
	తిరిగి ఖాళీ;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
స్థిర అక్షరం *
filter_list(స్థిరరాశి అక్షరం *proposal, స్థిరరాశి అక్షరం *filter, పూర్ణాంకం denylist)
{
	కొలత_t len = అక్షరశ్రేణి_పొడవు(proposal) + 1;
	అక్షరం *fix_prop = జ్ఞాపకం_ఇవ్వు(len);
	అక్షరం *orig_prop = strdup(proposal);
	అక్షరం *cp, *tmp;
	పూర్ణాంకం r;

	ఒకవేళ (fix_prop == ఖాళీ || orig_prop == ఖాళీ) {
		విడుదల(orig_prop);
		విడుదల(fix_prop);
		తిరిగి ఖాళీ;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	అయితే ((cp = strsep(&tmp, ",")) != ఖాళీ) {
		r = సరిపోలిక_నమూనా_list(cp, filter, 0);
		ఒకవేళ ((denylist && r != 1) || (!denylist && r == 1)) {
			ఒకవేళ (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	విడుదల(orig_prop);
	తిరిగి fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
అక్షరం *
సరిపోలిక_filter_denylist(స్థిరరాశి అక్షరం *proposal, స్థిరరాశి అక్షరం *filter)
{
	తిరిగి filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
అక్షరం *
సరిపోలిక_filter_allowlist(స్థిరరాశి అక్షరం *proposal, స్థిరరాశి అక్షరం *filter)
{
	తిరిగి filter_list(proposal, filter, 0);
}
