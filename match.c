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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
স্থির শূন্য
epsilon_closure(অক্ষর *states, ধ্রুবক অক্ষর *pattern, আকার_t M)
{
	আকার_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	জন্য (i = 0; i < M; i++) {
		যদি (!states[i] || pattern[i] != '*')
			চালু;
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
পূর্ণসংখ্যা
match_pattern(ধ্রুবক অক্ষর *s, ধ্রুবক অক্ষর *pattern)
{
	আকার_t M;
	আকার_t i;
	অক্ষর *states, *পরবর্তী_states, *tmp;
	পূর্ণসংখ্যা active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	যদি ((M = strlen(pattern)) == 0)
		ফেরত *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, আকার(*states));
	পরবর্তী_states = xcalloc(M + 1, আকার(*পরবর্তী_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	জন্য (; *s; s++) {
		memset(পরবর্তী_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		জন্য (i = 0; i < M; i++) {
			যদি (!states[i])
				চালু;
			যদি (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				পরবর্তী_states[i] = 1;
			} অন্যথা যদি (pattern[i] == '?' || pattern[i] == *s) {
				/*
				 * '?' matches any character, or we have
				 * a literal match.
				 */
				পরবর্তী_states[i + 1] = 1;
			}
		}

		/* Expand the reachable next states with epsilon transitions */
		epsilon_closure(পরবর্তী_states, pattern, M);

		/* Swap states and next_states */
		tmp = states;
		states = পরবর্তী_states;
		পরবর্তী_states = tmp;

		/* Check if we have any active pattern states left */
		active = 0;
		জন্য (i = 0; i <= M; i++) {
			যদি (states[i]) {
				active = 1;
				বিরতি;
			}
		}
		যদি (!active)
			যাও out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	মুক্ত(states);
	মুক্ত(পরবর্তী_states);
	ফেরত matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
পূর্ণসংখ্যা
match_pattern_list(ধ্রুবক অক্ষর *string, ধ্রুবক অক্ষর *pattern, পূর্ণসংখ্যা dolower)
{
	অক্ষর sub[1024];
	পূর্ণসংখ্যা negated;
	পূর্ণসংখ্যা got_positive;
	u_int i, subi, len = strlen(pattern);

	got_positive = 0;
	জন্য (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		যদি (pattern[i] == '!') {
			negated = 1;
			i++;
		} অন্যথা
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		জন্য (subi = 0;
		    i < len && subi < আকার(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)pattern[i]) ?
			    tolower((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		যদি (subi >= আকার(sub) - 1)
			ফেরত 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		যদি (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		যদি (match_pattern(string, sub)) {
			যদি (negated)
				ফেরত -1;		/* Negative */
			অন্যথা
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	ফেরত got_positive;
}

/* Match a list representing users or groups. */
পূর্ণসংখ্যা
match_usergroup_pattern_list(ধ্রুবক অক্ষর *string, ধ্রুবক অক্ষর *pattern)
{
#ifdef HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	ফেরত cygwin_ug_match_pattern_list(string, pattern);
#অন্যথা
	/* Case sensitive match */
	ফেরত match_pattern_list(string, pattern, 0);
#endif
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
পূর্ণসংখ্যা
match_hostname(ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *pattern)
{
	অক্ষর *hostcopy = xstrdup(host);
	পূর্ণসংখ্যা r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	মুক্ত(hostcopy);
	ফেরত r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
পূর্ণসংখ্যা
match_host_and_ip(ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ipaddr,
    ধ্রুবক অক্ষর *patterns)
{
	পূর্ণসংখ্যা mhost, mip;

	যদি ((mip = addr_match_list(ipaddr, patterns)) == -2)
		ফেরত -1; /* error in ipaddr match */
	অন্যথা যদি (host == ফাঁকা || ipaddr == ফাঁকা || mip == -1)
		ফেরত 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	যদি ((mhost = match_hostname(host, patterns)) == -1)
		ফেরত 0;
	/* no match at all */
	যদি (mhost == 0 && mip == 0)
		ফেরত 0;
	ফেরত 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
পূর্ণসংখ্যা
match_user(ধ্রুবক অক্ষর *user, ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ipaddr,
    ধ্রুবক অক্ষর *pattern)
{
	অক্ষর *p, *pat;
	পূর্ণসংখ্যা ret;

	/* test mode */
	যদি (user == ফাঁকা && host == ফাঁকা && ipaddr == ফাঁকা) {
		যদি ((p = strrchr(pattern, '@')) != ফাঁকা &&
		    match_host_and_ip(ফাঁকা, ফাঁকা, p + 1) < 0)
			ফেরত -1;
		ফেরত 0;
	}

	যদি (user == ফাঁকা)
		ফেরত 0; /* shouldn't happen */

	যদি (strrchr(pattern, '@') == ফাঁকা)
		ফেরত match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = strrchr(pat, '@');
	*p++ = '\0';

	যদি ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	মুক্ত(pat);

	ফেরত ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#define	MAX_PROP	40
#define	SEP	","
অক্ষর *
match_list(ধ্রুবক অক্ষর *client, ধ্রুবক অক্ষর *server, u_int *পরবর্তী)
{
	অক্ষর *sproposals[MAX_PROP];
	অক্ষর *c, *s, *p, *ret, *cp, *sp;
	পূর্ণসংখ্যা i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	জন্য ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		যদি (i < MAX_PROP)
			sproposals[i] = p;
		অন্যথা
			বিরতি;
	}
	nproposals = i;

	জন্য ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		জন্য (j = 0; j < nproposals; j++) {
			যদি (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				যদি (পরবর্তী != ফাঁকা)
					*পরবর্তী = (cp == ফাঁকা) ?
					    strlen(c) : (u_int)(cp - c);
				মুক্ত(c);
				মুক্ত(s);
				ফেরত ret;
			}
		}
	}
	যদি (পরবর্তী != ফাঁকা)
		*পরবর্তী = strlen(c);
	মুক্ত(c);
	মুক্ত(s);
	ফেরত ফাঁকা;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
স্থির অক্ষর *
filter_list(ধ্রুবক অক্ষর *proposal, ধ্রুবক অক্ষর *filter, পূর্ণসংখ্যা denylist)
{
	আকার_t len = strlen(proposal) + 1;
	অক্ষর *fix_prop = malloc(len);
	অক্ষর *orig_prop = strdup(proposal);
	অক্ষর *cp, *tmp;
	পূর্ণসংখ্যা r;

	যদি (fix_prop == ফাঁকা || orig_prop == ফাঁকা) {
		মুক্ত(orig_prop);
		মুক্ত(fix_prop);
		ফেরত ফাঁকা;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	যখন ((cp = strsep(&tmp, ",")) != ফাঁকা) {
		r = match_pattern_list(cp, filter, 0);
		যদি ((denylist && r != 1) || (!denylist && r == 1)) {
			যদি (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	মুক্ত(orig_prop);
	ফেরত fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
অক্ষর *
match_filter_denylist(ধ্রুবক অক্ষর *proposal, ধ্রুবক অক্ষর *filter)
{
	ফেরত filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
অক্ষর *
match_filter_allowlist(ধ্রুবক অক্ষর *proposal, ধ্রুবক অক্ষর *filter)
{
	ফেরত filter_list(proposal, filter, 0);
}
