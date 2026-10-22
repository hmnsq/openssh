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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <ctype.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>

#समावेश "xmalloc.h"
#समावेश "match.h"
#समावेश "misc.h"

/*
 * Computes the epsilon closure of an NFA set.
 * In our wildcard grammar, epsilon transitions only exist for '*' wildcards,
 * allowing us to transition from state i to i+1 without consuming input.
 *
 * This function modifies 'states' in place.
 */
अटल व्योम
epsilon_closure(अक्षर *states, स्थिर अक्षर *pattern, माप_प्रकार M)
{
	माप_प्रकार i;

	/* only need a forward pass as there are no back jumps in our grammar */
	क्रम (i = 0; i < M; i++) {
		अगर (!states[i] || pattern[i] != '*')
			जारी;
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
पूर्णांक
match_pattern(स्थिर अक्षर *s, स्थिर अक्षर *pattern)
{
	माप_प्रकार M;
	माप_प्रकार i;
	अक्षर *states, *अग्र_states, *tmp;
	पूर्णांक active, matched = 0;

	/* trivial case: empty pattern vs empty input */
	अगर ((M = म_माप(pattern)) == 0)
		वापस *s == '\0';

	/* A state for each pattern character, plus one final accepting state */
	states = xcalloc(M + 1, माप(*states));
	अग्र_states = xcalloc(M + 1, माप(*अग्र_states));

	/* Initial state: state 0 is active */
	states[0] = 1;
	/* Other states might be reachable now if the pattern starts with '*' */
	epsilon_closure(states, pattern, M);

	क्रम (; *s; s++) {
		स_रखो(अग्र_states, 0, M + 1);

		/* Calculate the reachable next states given the input char */
		क्रम (i = 0; i < M; i++) {
			अगर (!states[i])
				जारी;
			अगर (pattern[i] == '*') {
				/*
				 * '*' matches any character, so we can
				 * stay in state i
				 */
				अग्र_states[i] = 1;
			} अन्यथा अगर (pattern[i] == '?' || pattern[i] == *s) {
				/*
				 * '?' matches any character, or we have
				 * a literal match.
				 */
				अग्र_states[i + 1] = 1;
			}
		}

		/* Expand the reachable next states with epsilon transitions */
		epsilon_closure(अग्र_states, pattern, M);

		/* Swap states and next_states */
		tmp = states;
		states = अग्र_states;
		अग्र_states = tmp;

		/* Check if we have any active pattern states left */
		active = 0;
		क्रम (i = 0; i <= M; i++) {
			अगर (states[i]) {
				active = 1;
				अवरोध;
			}
		}
		अगर (!active)
			जाओ out; /* No active states, fail early */
	}
	/*
	 * We matched only if we ended up in the final, accepting state
	 * after consuming all the input.
	 */
	matched = states[M];
 out:
	मुक्त(states);
	मुक्त(अग्र_states);
	वापस matched;
}

/*
 * Tries to match the string against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
पूर्णांक
match_pattern_list(स्थिर अक्षर *string, स्थिर अक्षर *pattern, पूर्णांक dolower)
{
	अक्षर sub[1024];
	पूर्णांक negated;
	पूर्णांक got_positive;
	u_int i, subi, len = म_माप(pattern);

	got_positive = 0;
	क्रम (i = 0; i < len;) {
		/* Check if the subpattern is negated. */
		अगर (pattern[i] == '!') {
			negated = 1;
			i++;
		} अन्यथा
			negated = 0;

		/*
		 * Extract the subpattern up to a comma or end.  Convert the
		 * subpattern to lowercase.
		 */
		क्रम (subi = 0;
		    i < len && subi < माप(sub) - 1 && pattern[i] != ',';
		    subi++, i++)
			sub[subi] = dolower && है_बड़ा((u_char)pattern[i]) ?
			    छोटे((u_char)pattern[i]) : pattern[i];
		/* If subpattern too long, return failure (no match). */
		अगर (subi >= माप(sub) - 1)
			वापस 0;

		/* If the subpattern was terminated by a comma, then skip it. */
		अगर (i < len && pattern[i] == ',')
			i++;

		/* Null-terminate the subpattern. */
		sub[subi] = '\0';

		/* Try to match the subpattern against the string. */
		अगर (match_pattern(string, sub)) {
			अगर (negated)
				वापस -1;		/* Negative */
			अन्यथा
				got_positive = 1;	/* Positive */
		}
	}

	/*
	 * Return success if got a positive match.  If there was a negative
	 * match, we have already returned -1 and never get here.
	 */
	वापस got_positive;
}

/* Match a list representing users or groups. */
पूर्णांक
match_usergroup_pattern_list(स्थिर अक्षर *string, स्थिर अक्षर *pattern)
{
#अगर_घोषित HAVE_CYGWIN
	/* Windows usernames may be Unicode and are not case sensitive */
	वापस cygwin_ug_match_pattern_list(string, pattern);
#अन्यथा
	/* Case sensitive match */
	वापस match_pattern_list(string, pattern, 0);
#पूर्ण_अगर
}

/*
 * Tries to match the host name (which must be in all lowercase) against the
 * comma-separated sequence of subpatterns (each possibly preceded by ! to
 * indicate negation).  Returns -1 if negation matches, 1 if there is
 * a positive match, 0 if there is no match at all.
 */
पूर्णांक
match_hostname(स्थिर अक्षर *host, स्थिर अक्षर *pattern)
{
	अक्षर *hostcopy = xstrdup(host);
	पूर्णांक r;

	lowercase(hostcopy);
	r = match_pattern_list(hostcopy, pattern, 1);
	मुक्त(hostcopy);
	वापस r;
}

/*
 * returns 0 if we get a negative match for the hostname or the ip
 * or if we get no match at all.  returns -1 on error, or 1 on
 * successful match.
 */
पूर्णांक
match_host_and_ip(स्थिर अक्षर *host, स्थिर अक्षर *ipaddr,
    स्थिर अक्षर *patterns)
{
	पूर्णांक mhost, mip;

	अगर ((mip = addr_match_list(ipaddr, patterns)) == -2)
		वापस -1; /* error in ipaddr match */
	अन्यथा अगर (host == शून्य || ipaddr == शून्य || mip == -1)
		वापस 0; /* negative ip address match, or testing pattern */

	/* negative hostname match */
	अगर ((mhost = match_hostname(host, patterns)) == -1)
		वापस 0;
	/* no match at all */
	अगर (mhost == 0 && mip == 0)
		वापस 0;
	वापस 1;
}

/*
 * Match user, user@host_or_ip, user@host_or_ip_list against pattern.
 * If user, host and ipaddr are all NULL then validate pattern/
 * Returns -1 on invalid pattern, 0 on no match, 1 on match.
 */
पूर्णांक
match_user(स्थिर अक्षर *user, स्थिर अक्षर *host, स्थिर अक्षर *ipaddr,
    स्थिर अक्षर *pattern)
{
	अक्षर *p, *pat;
	पूर्णांक ret;

	/* test mode */
	अगर (user == शून्य && host == शून्य && ipaddr == शून्य) {
		अगर ((p = म_खोजप(pattern, '@')) != शून्य &&
		    match_host_and_ip(शून्य, शून्य, p + 1) < 0)
			वापस -1;
		वापस 0;
	}

	अगर (user == शून्य)
		वापस 0; /* shouldn't happen */

	अगर (म_खोजप(pattern, '@') == शून्य)
		वापस match_pattern(user, pattern);

	pat = xstrdup(pattern);
	p = म_खोजप(pat, '@');
	*p++ = '\0';

	अगर ((ret = match_pattern(user, pat)) == 1)
		ret = match_host_and_ip(host, ipaddr, p);
	मुक्त(pat);

	वापस ret;
}

/*
 * Returns first item from client-list that is also supported by server-list,
 * caller must free the returned string.
 */
#घोषणा	MAX_PROP	40
#घोषणा	SEP	","
अक्षर *
match_list(स्थिर अक्षर *client, स्थिर अक्षर *server, u_int *अग्र)
{
	अक्षर *sproposals[MAX_PROP];
	अक्षर *c, *s, *p, *ret, *cp, *sp;
	पूर्णांक i, j, nproposals;

	c = cp = xstrdup(client);
	s = sp = xstrdup(server);

	क्रम ((p = strsep(&sp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&sp, SEP)), i++) {
		अगर (i < MAX_PROP)
			sproposals[i] = p;
		अन्यथा
			अवरोध;
	}
	nproposals = i;

	क्रम ((p = strsep(&cp, SEP)), i=0; p && *p != '\0';
	    (p = strsep(&cp, SEP)), i++) {
		क्रम (j = 0; j < nproposals; j++) {
			अगर (म_भेद(p, sproposals[j]) == 0) {
				ret = xstrdup(p);
				अगर (अग्र != शून्य)
					*अग्र = (cp == शून्य) ?
					    म_माप(c) : (u_int)(cp - c);
				मुक्त(c);
				मुक्त(s);
				वापस ret;
			}
		}
	}
	अगर (अग्र != शून्य)
		*अग्र = म_माप(c);
	मुक्त(c);
	मुक्त(s);
	वापस शून्य;
}

/*
 * Filter proposal using pattern-list filter.
 * "denylist" determines sense of filter:
 * non-zero indicates that items matching filter should be excluded.
 * zero indicates that only items matching filter should be included.
 * returns NULL on allocation error, otherwise caller must free result.
 */
अटल अक्षर *
filter_list(स्थिर अक्षर *proposal, स्थिर अक्षर *filter, पूर्णांक denylist)
{
	माप_प्रकार len = म_माप(proposal) + 1;
	अक्षर *fix_prop = दो_स्मृति(len);
	अक्षर *orig_prop = strdup(proposal);
	अक्षर *cp, *tmp;
	पूर्णांक r;

	अगर (fix_prop == शून्य || orig_prop == शून्य) {
		मुक्त(orig_prop);
		मुक्त(fix_prop);
		वापस शून्य;
	}

	tmp = orig_prop;
	*fix_prop = '\0';
	जबतक ((cp = strsep(&tmp, ",")) != शून्य) {
		r = match_pattern_list(cp, filter, 0);
		अगर ((denylist && r != 1) || (!denylist && r == 1)) {
			अगर (*fix_prop != '\0')
				strlcat(fix_prop, ",", len);
			strlcat(fix_prop, cp, len);
		}
	}
	मुक्त(orig_prop);
	वापस fix_prop;
}

/*
 * Filters a comma-separated list of strings, excluding any entry matching
 * the 'filter' pattern list. Caller must free returned string.
 */
अक्षर *
match_filter_denylist(स्थिर अक्षर *proposal, स्थिर अक्षर *filter)
{
	वापस filter_list(proposal, filter, 1);
}

/*
 * Filters a comma-separated list of strings, including only entries matching
 * the 'filter' pattern list. Caller must free returned string.
 */
अक्षर *
match_filter_allowlist(स्थिर अक्षर *proposal, स्थिर अक्षर *filter)
{
	वापस filter_list(proposal, filter, 0);
}
