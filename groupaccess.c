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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <grp.h>
#ضمن <unistd.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <limits.h>

#ضمن "xmalloc.h"
#ضمن "groupaccess.h"
#ضمن "match.h"
#ضمن "log.h"

ساكن صحيح ngroups;
ساكن حرف **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
صحيح
ga_init(ثابت حرف *user, gid_t بنسټ)
{
	gid_t *groups_bygid;
	صحيح ongroups, i, j, retry = 0;
	بنية ډله *gr;

	إذا (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#إذا defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#د_که_پای

	groups_bygid = xcalloc(ngroups, حجم(*groups_bygid));
	طالما (getgrouplist(user, بنسټ, groups_bygid, &ngroups) == -1) {
		إذا (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (اوږد)بنسټ);
			حرر(groups_bygid);
			groups_bygid = عدم;
			ngroups = 0;
			أرجع 0;
		}
		إذا (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (اوږد)بنسټ,
			    (اوږد)ongroups, (اوږد)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    حجم(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, حجم(*groups_byname));

	لكل (i = 0, j = 0; i < ngroups; i++)
		إذا ((gr = getgrgid(groups_bygid[i])) != عدم)
			groups_byname[j++] = xstrdup(gr->gr_name);
	حرر(groups_bygid);
	أرجع (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
صحيح
ga_سمون(حرف * ثابت *groups, صحيح n)
{
	صحيح i, j;

	لكل (i = 0; i < ngroups; i++)
		لكل (j = 0; j < n; j++)
			إذا (سمون_نمونه(groups_byname[i], groups[j]))
				أرجع 1;
	أرجع 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
صحيح
ga_سمون_نمونه_list(ثابت حرف *ډله_نمونه)
{
	صحيح i, وموندل = 0;

	لكل (i = 0; i < ngroups; i++) {
		بدل (سمون_usergroup_نمونه_list(groups_byname[i],
		    ډله_نمونه)) {
		حالة -1:
			أرجع 0;	/* Negated match wins */
		حالة 0:
			استمر;
		حالة 1:
			وموندل = 1;
		}
	}
	أرجع وموندل;
}

/*
 * Free memory allocated for group access list.
 */
فراغ
ga_free(فراغ)
{
	صحيح i;

	إذا (ngroups > 0) {
		لكل (i = 0; i < ngroups; i++)
			حرر(groups_byname[i]);
		ngroups = 0;
		حرر(groups_byname);
		groups_byname = عدم;
	}
}
