/* $OpenBSD: groupaccess.c,v 1.18 2024/11/04 21:59:15 jca Exp $ */
/*
 * Copyright (c) 2001 Kevin Steves.  All rights reserved.
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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <grp.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "groupaccess.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "log.h"

સ્થિર પૂર્ણાંક ngroups;
સ્થિર અક્ષર **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
પૂર્ણાંક
ga_init(અચલ અક્ષર *user, gid_t base)
{
	gid_t *groups_bygid;
	પૂર્ણાંક ongroups, i, j, retry = 0;
	સંરચના group *gr;

	જો (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#જો defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#endif

	groups_bygid = xcalloc(ngroups, કદ(*groups_bygid));
	જ્યારે (getgrouplist(user, base, groups_bygid, &ngroups) == -1) {
		જો (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (long)base);
			મુક્ત(groups_bygid);
			groups_bygid = ખાલી;
			ngroups = 0;
			પાછા 0;
		}
		જો (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (long)base,
			    (long)ongroups, (long)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    કદ(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, કદ(*groups_byname));

	માટે (i = 0, j = 0; i < ngroups; i++)
		જો ((gr = getgrgid(groups_bygid[i])) != ખાલી)
			groups_byname[j++] = xstrdup(gr->gr_name);
	મુક્ત(groups_bygid);
	પાછા (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
પૂર્ણાંક
ga_match(અક્ષર * અચલ *groups, પૂર્ણાંક n)
{
	પૂર્ણાંક i, j;

	માટે (i = 0; i < ngroups; i++)
		માટે (j = 0; j < n; j++)
			જો (match_pattern(groups_byname[i], groups[j]))
				પાછા 1;
	પાછા 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
પૂર્ણાંક
ga_match_pattern_list(અચલ અક્ષર *group_pattern)
{
	પૂર્ણાંક i, found = 0;

	માટે (i = 0; i < ngroups; i++) {
		પસંદગી (match_usergroup_pattern_list(groups_byname[i],
		    group_pattern)) {
		સ્થિતિ -1:
			પાછા 0;	/* Negated match wins */
		સ્થિતિ 0:
			ચાલુ;
		સ્થિતિ 1:
			found = 1;
		}
	}
	પાછા found;
}

/*
 * Free memory allocated for group access list.
 */
શૂન્ય
ga_free(શૂન્ય)
{
	પૂર્ણાંક i;

	જો (ngroups > 0) {
		માટે (i = 0; i < ngroups; i++)
			મુક્ત(groups_byname[i]);
		ngroups = 0;
		મુક્ત(groups_byname);
		groups_byname = ખાલી;
	}
}
