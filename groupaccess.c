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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <grp.h>
#شامل <unistd.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <limits.h>

#شامل "xmalloc.h"
#شامل "groupaccess.h"
#شامل "match.h"
#شامل "log.h"

ساکن صحیح ngroups;
ساکن حرف **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
صحیح
ga_init(ثابت حرف *user, gid_t بنیاد)
{
	gid_t *groups_bygid;
	صحیح ongroups, i, j, retry = 0;
	ساخت گروہ *gr;

	اگر (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#اگر defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#اگر_ختم

	groups_bygid = xcalloc(ngroups, حجم(*groups_bygid));
	جب (getgrouplist(user, بنیاد, groups_bygid, &ngroups) == -1) {
		اگر (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (طویل)بنیاد);
			آزاد(groups_bygid);
			groups_bygid = تہی;
			ngroups = 0;
			واپس 0;
		}
		اگر (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (طویل)بنیاد,
			    (طویل)ongroups, (طویل)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    حجم(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, حجم(*groups_byname));

	برائے (i = 0, j = 0; i < ngroups; i++)
		اگر ((gr = getgrgid(groups_bygid[i])) != تہی)
			groups_byname[j++] = xstrdup(gr->gr_name);
	آزاد(groups_bygid);
	واپس (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
صحیح
ga_مطابقت(حرف * ثابت *groups, صحیح n)
{
	صحیح i, j;

	برائے (i = 0; i < ngroups; i++)
		برائے (j = 0; j < n; j++)
			اگر (مطابقت_نمونہ(groups_byname[i], groups[j]))
				واپس 1;
	واپس 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
صحیح
ga_مطابقت_نمونہ_list(ثابت حرف *گروہ_نمونہ)
{
	صحیح i, ملا = 0;

	برائے (i = 0; i < ngroups; i++) {
		انتخاب (مطابقت_usergroup_نمونہ_list(groups_byname[i],
		    گروہ_نمونہ)) {
		حالت -1:
			واپس 0;	/* Negated match wins */
		حالت 0:
			جاری;
		حالت 1:
			ملا = 1;
		}
	}
	واپس ملا;
}

/*
 * Free memory allocated for group access list.
 */
خالی
ga_free(خالی)
{
	صحیح i;

	اگر (ngroups > 0) {
		برائے (i = 0; i < ngroups; i++)
			آزاد(groups_byname[i]);
		ngroups = 0;
		آزاد(groups_byname);
		groups_byname = تہی;
	}
}
