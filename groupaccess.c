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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "groupaccess.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਸਥਿਰ ਪੂਰਨ ngroups;
ਸਥਿਰ ਅੱਖਰ **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
ਪੂਰਨ
ga_init(ਅਚਲ ਅੱਖਰ *user, gid_t ਅਧਾਰ)
{
	gid_t *groups_bygid;
	ਪੂਰਨ ongroups, i, j, retry = 0;
	ਬਣਤਰ ਸਮੂਹ *gr;

	ਜੇ (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#ਜੇ defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#ਜੇ_ਅੰਤ

	groups_bygid = xcalloc(ngroups, ਆਕਾਰ(*groups_bygid));
	ਜਦੋਂ (getgrouplist(user, ਅਧਾਰ, groups_bygid, &ngroups) == -1) {
		ਜੇ (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (ਲੰਮਾ)ਅਧਾਰ);
			ਮੁਕਤ(groups_bygid);
			groups_bygid = ਨਿਰਾ;
			ngroups = 0;
			ਵਾਪਸ 0;
		}
		ਜੇ (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (ਲੰਮਾ)ਅਧਾਰ,
			    (ਲੰਮਾ)ongroups, (ਲੰਮਾ)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    ਆਕਾਰ(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, ਆਕਾਰ(*groups_byname));

	ਲਈ (i = 0, j = 0; i < ngroups; i++)
		ਜੇ ((gr = getgrgid(groups_bygid[i])) != ਨਿਰਾ)
			groups_byname[j++] = xstrdup(gr->gr_name);
	ਮੁਕਤ(groups_bygid);
	ਵਾਪਸ (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
ਪੂਰਨ
ga_ਮੇਲ(ਅੱਖਰ * ਅਚਲ *groups, ਪੂਰਨ n)
{
	ਪੂਰਨ i, j;

	ਲਈ (i = 0; i < ngroups; i++)
		ਲਈ (j = 0; j < n; j++)
			ਜੇ (ਮੇਲ_ਨਮੂਨਾ(groups_byname[i], groups[j]))
				ਵਾਪਸ 1;
	ਵਾਪਸ 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
ਪੂਰਨ
ga_ਮੇਲ_ਨਮੂਨਾ_list(ਅਚਲ ਅੱਖਰ *ਸਮੂਹ_ਨਮੂਨਾ)
{
	ਪੂਰਨ i, ਮਿਲਿਆ = 0;

	ਲਈ (i = 0; i < ngroups; i++) {
		ਚੋਣ (ਮੇਲ_usergroup_ਨਮੂਨਾ_list(groups_byname[i],
		    ਸਮੂਹ_ਨਮੂਨਾ)) {
		ਹਾਲਤ -1:
			ਵਾਪਸ 0;	/* Negated match wins */
		ਹਾਲਤ 0:
			ਜਾਰੀ;
		ਹਾਲਤ 1:
			ਮਿਲਿਆ = 1;
		}
	}
	ਵਾਪਸ ਮਿਲਿਆ;
}

/*
 * Free memory allocated for group access list.
 */
ਖਾਲੀ
ga_free(ਖਾਲੀ)
{
	ਪੂਰਨ i;

	ਜੇ (ngroups > 0) {
		ਲਈ (i = 0; i < ngroups; i++)
			ਮੁਕਤ(groups_byname[i]);
		ngroups = 0;
		ਮੁਕਤ(groups_byname);
		groups_byname = ਨਿਰਾ;
	}
}
