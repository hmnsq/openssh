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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <grp.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "groupaccess.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ngroups;
ସ୍ଥିର ଅକ୍ଷର **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ga_init(ଅଚଳ ଅକ୍ଷର *user, gid_t base)
{
	gid_t *groups_bygid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ongroups, i, j, retry = 0;
	ସଂରଚନା group *gr;

	ଯଦି (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#ଯଦି defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#endif

	groups_bygid = xcalloc(ngroups, ଆକାର(*groups_bygid));
	ଯେତେବେଳେ (getgrouplist(user, base, groups_bygid, &ngroups) == -1) {
		ଯଦି (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (long)base);
			ମୁକ୍ତ(groups_bygid);
			groups_bygid = ଖାଲି;
			ngroups = 0;
			ଫେରନ୍ତୁ 0;
		}
		ଯଦି (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (long)base,
			    (long)ongroups, (long)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    ଆକାର(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, ଆକାର(*groups_byname));

	ପାଇଁ (i = 0, j = 0; i < ngroups; i++)
		ଯଦି ((gr = getgrgid(groups_bygid[i])) != ଖାଲି)
			groups_byname[j++] = xstrdup(gr->gr_name);
	ମୁକ୍ତ(groups_bygid);
	ଫେରନ୍ତୁ (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ga_match(ଅକ୍ଷର * ଅଚଳ *groups, ପୂର୍ଣ୍ଣସଂଖ୍ୟା n)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j;

	ପାଇଁ (i = 0; i < ngroups; i++)
		ପାଇଁ (j = 0; j < n; j++)
			ଯଦି (match_pattern(groups_byname[i], groups[j]))
				ଫେରନ୍ତୁ 1;
	ଫେରନ୍ତୁ 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ga_match_pattern_list(ଅଚଳ ଅକ୍ଷର *group_pattern)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, found = 0;

	ପାଇଁ (i = 0; i < ngroups; i++) {
		ବାଛ (match_usergroup_pattern_list(groups_byname[i],
		    group_pattern)) {
		ସ୍ଥିତି -1:
			ଫେରନ୍ତୁ 0;	/* Negated match wins */
		ସ୍ଥିତି 0:
			ଜାରି;
		ସ୍ଥିତି 1:
			found = 1;
		}
	}
	ଫେରନ୍ତୁ found;
}

/*
 * Free memory allocated for group access list.
 */
ଶୂନ୍ୟ
ga_free(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (ngroups > 0) {
		ପାଇଁ (i = 0; i < ngroups; i++)
			ମୁକ୍ତ(groups_byname[i]);
		ngroups = 0;
		ମୁକ୍ତ(groups_byname);
		groups_byname = ଖାଲି;
	}
}
