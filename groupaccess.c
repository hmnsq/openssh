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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "groupaccess.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "log.h"

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ngroups;
ಸ್ಥಿರ ಅಕ್ಷರ **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
ಪೂರ್ಣಾಂಕ
ga_init(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, gid_t ತಳ)
{
	gid_t *groups_bygid;
	ಪೂರ್ಣಾಂಕ ongroups, i, j, retry = 0;
	ರಚನೆ ಗುಂಪು *gr;

	ಆದರೆ (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#ಆದರೆ defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#ಆದರೆ_ಅಂತ್ಯ

	groups_bygid = xcalloc(ngroups, ಗಾತ್ರ(*groups_bygid));
	ಆಗ (getgrouplist(user, ತಳ, groups_bygid, &ngroups) == -1) {
		ಆದರೆ (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (ದೀರ್ಘ)ತಳ);
			ಬಿಡುಗಡೆ(groups_bygid);
			groups_bygid = ಖಾಲಿ;
			ngroups = 0;
			ಹಿಂತಿರುಗಿ 0;
		}
		ಆದರೆ (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (ದೀರ್ಘ)ತಳ,
			    (ದೀರ್ಘ)ongroups, (ದೀರ್ಘ)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    ಗಾತ್ರ(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, ಗಾತ್ರ(*groups_byname));

	ಗಾಗಿ (i = 0, j = 0; i < ngroups; i++)
		ಆದರೆ ((gr = getgrgid(groups_bygid[i])) != ಖಾಲಿ)
			groups_byname[j++] = xstrdup(gr->gr_name);
	ಬಿಡುಗಡೆ(groups_bygid);
	ಹಿಂತಿರುಗಿ (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
ಪೂರ್ಣಾಂಕ
ga_ಹೊಂದಿಕೆ(ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *groups, ಪೂರ್ಣಾಂಕ n)
{
	ಪೂರ್ಣಾಂಕ i, j;

	ಗಾಗಿ (i = 0; i < ngroups; i++)
		ಗಾಗಿ (j = 0; j < n; j++)
			ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ(groups_byname[i], groups[j]))
				ಹಿಂತಿರುಗಿ 1;
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
ಪೂರ್ಣಾಂಕ
ga_ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಗುಂಪು_ನಮೂನೆ)
{
	ಪೂರ್ಣಾಂಕ i, ಸಿಕ್ಕಿತು = 0;

	ಗಾಗಿ (i = 0; i < ngroups; i++) {
		ಆಯ್ಕೆ (ಹೊಂದಿಕೆ_usergroup_ನಮೂನೆ_list(groups_byname[i],
		    ಗುಂಪು_ನಮೂನೆ)) {
		ಸ್ಥಿತಿ -1:
			ಹಿಂತಿರುಗಿ 0;	/* Negated match wins */
		ಸ್ಥಿತಿ 0:
			ಮುಂದುವರಿ;
		ಸ್ಥಿತಿ 1:
			ಸಿಕ್ಕಿತು = 1;
		}
	}
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
}

/*
 * Free memory allocated for group access list.
 */
ಶೂನ್ಯ
ga_free(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (ngroups > 0) {
		ಗಾಗಿ (i = 0; i < ngroups; i++)
			ಬಿಡುಗಡೆ(groups_byname[i]);
		ngroups = 0;
		ಬಿಡುಗಡೆ(groups_byname);
		groups_byname = ಖಾಲಿ;
	}
}
