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

static 정수 ngroups;
static char **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
정수
ga_init(const char *user, gid_t base)
{
	gid_t *groups_bygid;
	정수 ongroups, i, j, retry = 0;
	struct group *gr;

	만약 (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#만약 defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#endif

	groups_bygid = xcalloc(ngroups, sizeof(*groups_bygid));
	동안 (getgrouplist(user, base, groups_bygid, &ngroups) == -1) {
		만약 (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (long)base);
			free(groups_bygid);
			groups_bygid = NULL;
			ngroups = 0;
			반환 0;
		}
		만약 (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (long)base,
			    (long)ongroups, (long)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    sizeof(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, sizeof(*groups_byname));

	위해 (i = 0, j = 0; i < ngroups; i++)
		만약 ((gr = getgrgid(groups_bygid[i])) != NULL)
			groups_byname[j++] = xstrdup(gr->gr_name);
	free(groups_bygid);
	반환 (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
정수
ga_match(char * const *groups, 정수 n)
{
	정수 i, j;

	위해 (i = 0; i < ngroups; i++)
		위해 (j = 0; j < n; j++)
			만약 (match_pattern(groups_byname[i], groups[j]))
				반환 1;
	반환 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
정수
ga_match_pattern_list(const char *group_pattern)
{
	정수 i, found = 0;

	위해 (i = 0; i < ngroups; i++) {
		switch (match_usergroup_pattern_list(groups_byname[i],
		    group_pattern)) {
		case -1:
			반환 0;	/* Negated match wins */
		case 0:
			continue;
		case 1:
			found = 1;
		}
	}
	반환 found;
}

/*
 * Free memory allocated for group access list.
 */
void
ga_free(void)
{
	정수 i;

	만약 (ngroups > 0) {
		위해 (i = 0; i < ngroups; i++)
			free(groups_byname[i]);
		ngroups = 0;
		free(groups_byname);
		groups_byname = NULL;
	}
}
