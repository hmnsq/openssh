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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <grp.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <limits.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "groupaccess.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "log.h"

স্থির পূর্ণাঙ্ক ngroups;
স্থির ৱর্ণ **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
পূর্ণাঙ্ক
ga_init(ধ্রুৱ ৱর্ণ *user, gid_t base)
{
	gid_t *groups_bygid;
	পূর্ণাঙ্ক ongroups, i, j, retry = 0;
	সংরচনা group *gr;

	যদি (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#যদি defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#endif

	groups_bygid = xcalloc(ngroups, পরিমাণ(*groups_bygid));
	যেতিয়ালৈ (getgrouplist(user, base, groups_bygid, &ngroups) == -1) {
		যদি (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (long)base);
			মুক্ত(groups_bygid);
			groups_bygid = রিক্ত;
			ngroups = 0;
			ঘূৰাই 0;
		}
		যদি (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (long)base,
			    (long)ongroups, (long)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    পরিমাণ(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, পরিমাণ(*groups_byname));

	বাবে (i = 0, j = 0; i < ngroups; i++)
		যদি ((gr = getgrgid(groups_bygid[i])) != রিক্ত)
			groups_byname[j++] = xstrdup(gr->gr_name);
	মুক্ত(groups_bygid);
	ঘূৰাই (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
পূর্ণাঙ্ক
ga_match(ৱর্ণ * ধ্রুৱ *groups, পূর্ণাঙ্ক n)
{
	পূর্ণাঙ্ক i, j;

	বাবে (i = 0; i < ngroups; i++)
		বাবে (j = 0; j < n; j++)
			যদি (match_pattern(groups_byname[i], groups[j]))
				ঘূৰাই 1;
	ঘূৰাই 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
পূর্ণাঙ্ক
ga_match_pattern_list(ধ্রুৱ ৱর্ণ *group_pattern)
{
	পূর্ণাঙ্ক i, found = 0;

	বাবে (i = 0; i < ngroups; i++) {
		ৱিকল্প (match_usergroup_pattern_list(groups_byname[i],
		    group_pattern)) {
		পক্ষ -1:
			ঘূৰাই 0;	/* Negated match wins */
		পক্ষ 0:
			অনুৱর্ত;
		পক্ষ 1:
			found = 1;
		}
	}
	ঘূৰাই found;
}

/*
 * Free memory allocated for group access list.
 */
শূন্য
ga_free(শূন্য)
{
	পূর্ণাঙ্ক i;

	যদি (ngroups > 0) {
		বাবে (i = 0; i < ngroups; i++)
			মুক্ত(groups_byname[i]);
		ngroups = 0;
		মুক্ত(groups_byname);
		groups_byname = রিক্ত;
	}
}
