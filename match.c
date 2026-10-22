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
ساکن خالی
epsilon_احاطہ(حرف *حالتیں, ثابت حرف *نمونہ, سائز_t M)
{
	سائز_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	برائے (i = 0; i < M; i++) {
		اگر (!حالتیں[i] || نمونہ[i] != '*')
			جاری;
		/*
		 * State i is active, and pattern[i] is '*', so we can
		 * epsilon-transition to i+1.
		 */
		حالتیں[i + 1] = 1;
	}
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match. Uses an NFA internally.
 */
صحیح
مطابقت_نمونہ(ثابت حرف *s, ثابت حرف *نمونہ)
{
	سائز_t M;
	سائز_t i;
	حرف *حالتیں, *اگلا_حالتیں, *tmp;
	صحیح فعال, matched = 0;

	/* trivial case: empty pattern vs empty input */
	اگر ((M = لڑی_لمبائی(نمونہ)) == 0)
		واپس *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	حالتیں = xcalloc(M + 1, حجم(*حالتیں));
	اگلا_حالتیں = xcalloc(M + 1, حجم(*اگلا_حالتیں));

	/* Initial state: state 0 is active */
	حالتیں[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_احاطہ(حالتیں, نمونہ, M);

	برائے (; *s; s++) {
		memset(اگلا_حالتیں, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		برائے (i = 0; i < M; i++) {
			اگر (!حالتیں[i])
				جاری;
			اگر (نمونہ[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				اگلا_حالتیں[i] = 1;
			} ورنہ اگر (نمونہ[i] == '?' || نمونہ[i] == *s) {
				/*
				 * '?' matches any character, or we have
				 * a literal match.
				 */
				اگلا_حالتیں[i + 1] = 1;
			}
		}

		/* Expand the reachable next states with epsilon transitions */
		epsilon_احاطہ(اگلا_حالتیں, نمونہ, M);

		/* Swap states and next_states */
		tmp = حالتیں;
		حالتیں = اگلا_حالتیں;
		اگلا_حالتیں = tmp;

		/* Check if we have any active pattern states left */
		فعال = 0;
		برائے (i = 0; i <= M; i++) {
			اگر (حالتیں[i]) {
				فعال = 1;
				توڑو;
			}
		}
		اگر (!فعال)
			جاؤ برآمد; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = حالتیں[M];
 برآمد:
	آزاد(حالتیں);
	آزاد(اگلا_حالتیں);
	واپس matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
صحیح
مطابقت_نمونہ_list(ثابت حرف *string, ثابت حرف *نمونہ, صحیح dolower)
{
	حرف sub[1024];
	صحیح negated;
	صحیح got_مثبت;
	u_int i, subi, len = لڑی_لمبائی(نمونہ);

	got_مثبت = 0;
	برائے (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		اگر (نمونہ[i] == '!') {
			negated = 1;
			i++;
		} ورنہ
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		برائے (subi = 0;
		    i < len && subi < حجم(sub) - 1 && نمونہ[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)نمونہ[i]) ?
			    tolower((u_char)نمونہ[i]) : نمونہ[i];
		/* If subpattern too long, return failure (no match). */
		اگر (subi >= حجم(sub) - 1)
			واپس 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		اگر (i < len && نمونہ[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		اگر (مطابقت_نمونہ(string, sub)) {
			اگر (negated)
				واپس -1;		/* Negative */
			ورنہ
				got_مثبت = 1;	/*مثبت*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	واپس got_مثبت;
}

/* Match a list representing users or groups. */
صحیح
مطابقت_usergroup_نمونہ_list(ثابت حرف *string, ثابت حرف *نمونہ)
{
#اگر_تعریف_شدہ HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	واپس cygwin_ug_مطابقت_نمونہ_list(string, نمونہ);
#ورنہ
	/* Case sensitive match */
	واپس مطابقت_نمونہ_list(string, نمونہ, 0);
#اگر_ختم
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
صحیح
مطابقت_hostname(ثابت حرف *host, ثابت حرف *نمونہ)
{
	حرف *hostcopy = xstrdup(host);
	صحیح r;

	lowercase(hostcopy);
	r = مطابقت_نمونہ_list(hostcopy, نمونہ, 1);
	آزاد(hostcopy);
	واپس r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
صحیح
مطابقت_host_and_ip(ثابت حرف *host, ثابت حرف *ipaddr,
    ثابت حرف *patterns)
{
	صحیح mhost, mip;

	اگر ((mip = addr_مطابقت_list(ipaddr, patterns)) == -2)
		واپس -1; /* error in ipaddr match */
	ورنہ اگر (host == تہی || ipaddr == تہی || mip == -1)
		واپس 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	اگر ((mhost = مطابقت_hostname(host, patterns)) == -1)
		واپس 0;
	/* no match at all */
	اگر (mhost == 0 && mip == 0)
		واپس 0;
	واپس 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
صحیح
مطابقت_user(ثابت حرف *user, ثابت حرف *host, ثابت حرف *ipaddr,
    ثابت حرف *نمونہ)
{
	حرف *p, *pat;
	صحیح ret;

	/* test mode */
	اگر (user == تہی && host == تہی && ipaddr == تہی) {
		اگر ((p = strrchr(نمونہ, '@')) != تہی &&
		    مطابقت_host_and_ip(تہی, تہی, p + 1) < 0)
			واپس -1;
		واپس 0;
	}

	اگر (user == تہی)
		واپس 0; /* shouldn't happen */

	اگر (strrchr(نمونہ, '@') == تہی)
		واپس مطابقت_نمونہ(user, نمونہ);

	pat = xstrdup(نمونہ);
	p = strrchr(pat, '@');
	*p++ = '\0';

	اگر ((ret = مطابقت_نمونہ(user, pat)) == 1)
		ret = مطابقت_host_and_ip(host, ipaddr, p);
	آزاد(pat);

	واپس ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#تعریف_کرو	MAX_PROP	40
#تعریف_کرو	SEP	","
حرف *
مطابقت_list(ثابت حرف *client, ثابت حرف *server, u_int *اگلا)
{
	حرف *sproposals[MAX_PROP];
	حرف *c, *s, *p, *ret, *cp, *sp;
	صحیح i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	برائے ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		اگر (i < MAX_PROP)
			sproposals[i] = p;
		ورنہ
			توڑو;
	}
	nproposals = i;

	برائے ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		برائے (j = 0; j < nproposals; j++) {
			اگر (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				اگر (اگلا != تہی)
					*اگلا = (cp == تہی) ?
					    لڑی_لمبائی(c) : (u_int)(cp - c);
				آزاد(c);
				آزاد(s);
				واپس ret;
			}
		}
	}
	اگر (اگلا != تہی)
		*اگلا = لڑی_لمبائی(c);
	آزاد(c);
	آزاد(s);
	واپس تہی;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
ساکن حرف *
filter_list(ثابت حرف *proposal, ثابت حرف *filter, صحیح denylist)
{
	سائز_t len = لڑی_لمبائی(proposal) + 1;
	حرف *fix_prop = حافظہ_دو(len);
	حرف *orig_prop = strdup(proposal);
	حرف *cp, *tmp;
	صحیح r;

	اگر (fix_prop == تہی || orig_prop == تہی) {
		آزاد(orig_prop);
		آزاد(fix_prop);
		واپس تہی;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	جب ((cp = strsep(&tmp, ",")) != تہی) {
		r = مطابقت_نمونہ_list(cp, filter, 0);
		اگر ((denylist && r != 1) || (!denylist && r == 1)) {
			اگر (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	آزاد(orig_prop);
	واپس fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
حرف *
مطابقت_filter_denylist(ثابت حرف *proposal, ثابت حرف *filter)
{
	واپس filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
حرف *
مطابقت_filter_allowlist(ثابت حرف *proposal, ثابت حرف *filter)
{
	واپس filter_list(proposal, filter, 0);
}
