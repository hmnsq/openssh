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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <ctype.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>

#ضمن "xmalloc.h"
#ضمن "match.h"
#ضمن "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
ساكن فراغ
epsilon_گھیرا(حرف *حالتاں, ثابت حرف *نمونہ, ناپ_t M)
{
	ناپ_t i;

	/* only need a forward pass as there are no back jumps in our grammar */
	لكل (i = 0; i < M; i++) {
		إذا (!حالتاں[i] || نمونہ[i] != '*')
			استمر;
		/*
		 * State i is active, and pattern[i] is '*', so we can
		 * epsilon-transition to i+1.
		 */
		حالتاں[i + 1] = 1;
	}
}

/*
 * Returns true if the given string matches the pattern (which may contain ?
 * and * as wildcards), and zero if it does not match. Uses an NFA internally.
 */
صحيح
میل_نمونہ(ثابت حرف *s, ثابت حرف *نمونہ)
{
	ناپ_t M;
	ناپ_t i;
	حرف *حالتاں, *اگلا_حالتاں, *tmp;
	صحيح سرگرم, matched = 0;

	/* trivial case: empty pattern vs empty input */
	إذا ((M = لڑی_لمبائی(نمونہ)) == 0)
		أرجع *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	حالتاں = xcalloc(M + 1, حجم(*حالتاں));
	اگلا_حالتاں = xcalloc(M + 1, حجم(*اگلا_حالتاں));

	/* Initial state: state 0 is active */
	حالتاں[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_گھیرا(حالتاں, نمونہ, M);

	لكل (; *s; s++) {
		memset(اگلا_حالتاں, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		لكل (i = 0; i < M; i++) {
			إذا (!حالتاں[i])
				استمر;
			إذا (نمونہ[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				اگلا_حالتاں[i] = 1;
			} وإلا إذا (نمونہ[i] == '?' || نمونہ[i] == *s) {
				/*
				 * '?' matches any character, or we have
				 * a literal match.
				 */
				اگلا_حالتاں[i + 1] = 1;
			}
		}

		/* Expand the reachable next states with epsilon transitions */
		epsilon_گھیرا(اگلا_حالتاں, نمونہ, M);

		/* Swap states and next_states */
		tmp = حالتاں;
		حالتاں = اگلا_حالتاں;
		اگلا_حالتاں = tmp;

		/* Check if we have any active pattern states left */
		سرگرم = 0;
		لكل (i = 0; i <= M; i++) {
			إذا (حالتاں[i]) {
				سرگرم = 1;
				اكسر;
			}
		}
		إذا (!سرگرم)
			اذهب باہرلا; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = حالتاں[M];
 باہرلا:
	حرر(حالتاں);
	حرر(اگلا_حالتاں);
	أرجع matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
صحيح
میل_نمونہ_list(ثابت حرف *string, ثابت حرف *نمونہ, صحيح dolower)
{
	حرف sub[1024];
	صحيح negated;
	صحيح got_مثبت;
	u_int i, subi, len = لڑی_لمبائی(نمونہ);

	got_مثبت = 0;
	لكل (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		إذا (نمونہ[i] == '!') {
			negated = 1;
			i++;
		} وإلا
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		لكل (subi = 0;
		    i < len && subi < حجم(sub) - 1 && نمونہ[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && isupper((u_char)نمونہ[i]) ?
			    tolower((u_char)نمونہ[i]) : نمونہ[i];
		/* If subpattern too long, return failure (no match). */
		إذا (subi >= حجم(sub) - 1)
			أرجع 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		إذا (i < len && نمونہ[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		إذا (میل_نمونہ(string, sub)) {
			إذا (negated)
				أرجع -1;		/* Negative */
			وإلا
				got_مثبت = 1;	/*مثبت*/
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	أرجع got_مثبت;
}

/* Match a list representing users or groups. */
صحيح
میل_usergroup_نمونہ_list(ثابت حرف *string, ثابت حرف *نمونہ)
{
#جے_تعریف_شدہ HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	أرجع cygwin_ug_میل_نمونہ_list(string, نمونہ);
#وإلا
	/* Case sensitive match */
	أرجع میل_نمونہ_list(string, نمونہ, 0);
#جے_انت
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
صحيح
میل_hostname(ثابت حرف *host, ثابت حرف *نمونہ)
{
	حرف *hostcopy = xstrdup(host);
	صحيح r;

	lowercase(hostcopy);
	r = میل_نمونہ_list(hostcopy, نمونہ, 1);
	حرر(hostcopy);
	أرجع r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
صحيح
میل_host_and_ip(ثابت حرف *host, ثابت حرف *ipaddr,
    ثابت حرف *patterns)
{
	صحيح mhost, mip;

	إذا ((mip = addr_میل_list(ipaddr, patterns)) == -2)
		أرجع -1; /* error in ipaddr match */
	وإلا إذا (host == عدم || ipaddr == عدم || mip == -1)
		أرجع 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	إذا ((mhost = میل_hostname(host, patterns)) == -1)
		أرجع 0;
	/* no match at all */
	إذا (mhost == 0 && mip == 0)
		أرجع 0;
	أرجع 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
صحيح
میل_user(ثابت حرف *user, ثابت حرف *host, ثابت حرف *ipaddr,
    ثابت حرف *نمونہ)
{
	حرف *p, *pat;
	صحيح ret;

	/* test mode */
	إذا (user == عدم && host == عدم && ipaddr == عدم) {
		إذا ((p = strrchr(نمونہ, '@')) != عدم &&
		    میل_host_and_ip(عدم, عدم, p + 1) < 0)
			أرجع -1;
		أرجع 0;
	}

	إذا (user == عدم)
		أرجع 0; /* shouldn't happen */

	إذا (strrchr(نمونہ, '@') == عدم)
		أرجع میل_نمونہ(user, نمونہ);

	pat = xstrdup(نمونہ);
	p = strrchr(pat, '@');
	*p++ = '\0';

	إذا ((ret = میل_نمونہ(user, pat)) == 1)
		ret = میل_host_and_ip(host, ipaddr, p);
	حرر(pat);

	أرجع ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#تعریف_کرو	MAX_PROP	40
#تعریف_کرو	SEP	","
حرف *
میل_list(ثابت حرف *client, ثابت حرف *server, u_int *اگلا)
{
	حرف *sproposals[MAX_PROP];
	حرف *c, *s, *p, *ret, *cp, *sp;
	صحيح i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	لكل ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		إذا (i < MAX_PROP)
			sproposals[i] = p;
		وإلا
			اكسر;
	}
	nproposals = i;

	لكل ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		لكل (j = 0; j < nproposals; j++) {
			إذا (strcmp(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				إذا (اگلا != عدم)
					*اگلا = (cp == عدم) ?
					    لڑی_لمبائی(c) : (u_int)(cp - c);
				حرر(c);
				حرر(s);
				أرجع ret;
			}
		}
	}
	إذا (اگلا != عدم)
		*اگلا = لڑی_لمبائی(c);
	حرر(c);
	حرر(s);
	أرجع عدم;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
ساكن حرف *
filter_list(ثابت حرف *proposal, ثابت حرف *filter, صحيح denylist)
{
	ناپ_t len = لڑی_لمبائی(proposal) + 1;
	حرف *fix_prop = حافظہ_دیو(len);
	حرف *orig_prop = strdup(proposal);
	حرف *cp, *tmp;
	صحيح r;

	إذا (fix_prop == عدم || orig_prop == عدم) {
		حرر(orig_prop);
		حرر(fix_prop);
		أرجع عدم;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	طالما ((cp = strsep(&tmp, ",")) != عدم) {
		r = میل_نمونہ_list(cp, filter, 0);
		إذا ((denylist && r != 1) || (!denylist && r == 1)) {
			إذا (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	حرر(orig_prop);
	أرجع fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
حرف *
میل_filter_denylist(ثابت حرف *proposal, ثابت حرف *filter)
{
	أرجع filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
حرف *
میل_filter_allowlist(ثابت حرف *proposal, ثابت حرف *filter)
{
	أرجع filter_list(proposal, filter, 0);
}
