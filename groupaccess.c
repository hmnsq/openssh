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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <grp.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "groupaccess.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "log.h"

స్థిర పూర్ణాంకం ngroups;
స్థిర అక్షరం **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
పూర్ణాంకం
ga_init(స్థిరరాశి అక్షరం *user, gid_t పునాది)
{
	gid_t *groups_bygid;
	పూర్ణాంకం ongroups, i, j, retry = 0;
	నిర్మాణం సమూహం *gr;

	ఒకవేళ (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#ఒకవేళ defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#అయితే_ముగింపు

	groups_bygid = xcalloc(ngroups, పరిమాణం(*groups_bygid));
	అయితే (getgrouplist(user, పునాది, groups_bygid, &ngroups) == -1) {
		ఒకవేళ (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (దీర్ఘ)పునాది);
			విడుదల(groups_bygid);
			groups_bygid = ఖాళీ;
			ngroups = 0;
			తిరిగి 0;
		}
		ఒకవేళ (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (దీర్ఘ)పునాది,
			    (దీర్ఘ)ongroups, (దీర్ఘ)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    పరిమాణం(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, పరిమాణం(*groups_byname));

	కొరకు (i = 0, j = 0; i < ngroups; i++)
		ఒకవేళ ((gr = getgrgid(groups_bygid[i])) != ఖాళీ)
			groups_byname[j++] = xstrdup(gr->gr_name);
	విడుదల(groups_bygid);
	తిరిగి (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
పూర్ణాంకం
ga_సరిపోలిక(అక్షరం * స్థిరరాశి *groups, పూర్ణాంకం n)
{
	పూర్ణాంకం i, j;

	కొరకు (i = 0; i < ngroups; i++)
		కొరకు (j = 0; j < n; j++)
			ఒకవేళ (సరిపోలిక_నమూనా(groups_byname[i], groups[j]))
				తిరిగి 1;
	తిరిగి 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
పూర్ణాంకం
ga_సరిపోలిక_నమూనా_list(స్థిరరాశి అక్షరం *సమూహం_నమూనా)
{
	పూర్ణాంకం i, దొరికింది = 0;

	కొరకు (i = 0; i < ngroups; i++) {
		ఎంపిక (సరిపోలిక_usergroup_నమూనా_list(groups_byname[i],
		    సమూహం_నమూనా)) {
		స్థితి -1:
			తిరిగి 0;	/* Negated match wins */
		స్థితి 0:
			కొనసాగు;
		స్థితి 1:
			దొరికింది = 1;
		}
	}
	తిరిగి దొరికింది;
}

/*
 * Free memory allocated for group access list.
 */
శూన్య
ga_free(శూన్య)
{
	పూర్ణాంకం i;

	ఒకవేళ (ngroups > 0) {
		కొరకు (i = 0; i < ngroups; i++)
			విడుదల(groups_byname[i]);
		ngroups = 0;
		విడుదల(groups_byname);
		groups_byname = ఖాళీ;
	}
}
