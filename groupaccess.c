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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <grp.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "groupaccess.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "log.h"

স্থির পূর্ণসংখ্যা ngroups;
স্থির অক্ষর **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
পূর্ণসংখ্যা
ga_init(ধ্রুবক অক্ষর *user, gid_t base)
{
	gid_t *groups_bygid;
	পূর্ণসংখ্যা ongroups, i, j, retry = 0;
	কাঠামো group *gr;

	যদি (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#যদি defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#endif

	groups_bygid = xcalloc(ngroups, আকার(*groups_bygid));
	যখন (getgrouplist(user, base, groups_bygid, &ngroups) == -1) {
		যদি (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (long)base);
			মুক্ত(groups_bygid);
			groups_bygid = ফাঁকা;
			ngroups = 0;
			ফেরত 0;
		}
		যদি (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (long)base,
			    (long)ongroups, (long)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    আকার(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, আকার(*groups_byname));

	জন্য (i = 0, j = 0; i < ngroups; i++)
		যদি ((gr = getgrgid(groups_bygid[i])) != ফাঁকা)
			groups_byname[j++] = xstrdup(gr->gr_name);
	মুক্ত(groups_bygid);
	ফেরত (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
পূর্ণসংখ্যা
ga_match(অক্ষর * ধ্রুবক *groups, পূর্ণসংখ্যা n)
{
	পূর্ণসংখ্যা i, j;

	জন্য (i = 0; i < ngroups; i++)
		জন্য (j = 0; j < n; j++)
			যদি (match_pattern(groups_byname[i], groups[j]))
				ফেরত 1;
	ফেরত 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
পূর্ণসংখ্যা
ga_match_pattern_list(ধ্রুবক অক্ষর *group_pattern)
{
	পূর্ণসংখ্যা i, found = 0;

	জন্য (i = 0; i < ngroups; i++) {
		নির্বাচন (match_usergroup_pattern_list(groups_byname[i],
		    group_pattern)) {
		ক্ষেত্র -1:
			ফেরত 0;	/* Negated match wins */
		ক্ষেত্র 0:
			চালু;
		ক্ষেত্র 1:
			found = 1;
		}
	}
	ফেরত found;
}

/*
 * Free memory allocated for group access list.
 */
শূন্য
ga_free(শূন্য)
{
	পূর্ণসংখ্যা i;

	যদি (ngroups > 0) {
		জন্য (i = 0; i < ngroups; i++)
			মুক্ত(groups_byname[i]);
		ngroups = 0;
		মুক্ত(groups_byname);
		groups_byname = ফাঁকা;
	}
}
