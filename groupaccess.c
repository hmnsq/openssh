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

#include "includes.h"

#include <sys/types.h>

#include <grp.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "xmalloc.h"
#include "groupaccess.h"
#include "match.h"
#include "log.h"

static puur_naa_nka ngroups;
static var_na **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
puur_naa_nka
ga_init(const var_na *user, gid_t base)
{
	gid_t *groups_bygid;
	puur_naa_nka ongroups, i, j, retry = 0;
	sa_nracanaa group *gr;

	ᱡᱩᱫᱤ (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#ᱡᱩᱫᱤ defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#endif

	groups_bygid = xcalloc(ngroups, parimaa_na(*groups_bygid));
	ᱡᱚᱠᱷᱚᱱ (getgrouplist(user, base, groups_bygid, &ngroups) == -1) {
		ᱡᱩᱫᱤ (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (long)base);
			free(groups_bygid);
			groups_bygid = NULL;
			ngroups = 0;
			ᱨᱩᱣᱟᱹᱲ 0;
		}
		ᱡᱩᱫᱤ (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (long)base,
			    (long)ongroups, (long)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    parimaa_na(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, parimaa_na(*groups_byname));

	for (i = 0, j = 0; i < ngroups; i++)
		ᱡᱩᱫᱤ ((gr = getgrgid(groups_bygid[i])) != NULL)
			groups_byname[j++] = xstrdup(gr->gr_name);
	free(groups_bygid);
	ᱨᱩᱣᱟᱹᱲ (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
puur_naa_nka
ga_match(var_na * const *groups, puur_naa_nka n)
{
	puur_naa_nka i, j;

	for (i = 0; i < ngroups; i++)
		for (j = 0; j < n; j++)
			ᱡᱩᱫᱤ (match_pattern(groups_byname[i], groups[j]))
				ᱨᱩᱣᱟᱹᱲ 1;
	ᱨᱩᱣᱟᱹᱲ 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
puur_naa_nka
ga_match_pattern_list(const var_na *group_pattern)
{
	puur_naa_nka i, found = 0;

	for (i = 0; i < ngroups; i++) {
		switch (match_usergroup_pattern_list(groups_byname[i],
		    group_pattern)) {
		pak_sa -1:
			ᱨᱩᱣᱟᱹᱲ 0;	/* Negated match wins */
		pak_sa 0:
			continue;
		pak_sa 1:
			found = 1;
		}
	}
	ᱨᱩᱣᱟᱹᱲ found;
}

/*
 * Free memory allocated for group access list.
 */
void
ga_free(void)
{
	puur_naa_nka i;

	ᱡᱩᱫᱤ (ngroups > 0) {
		for (i = 0; i < ngroups; i++)
			free(groups_byname[i]);
		ngroups = 0;
		free(groups_byname);
		groups_byname = NULL;
	}
}
