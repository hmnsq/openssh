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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <grp.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "groupaccess.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "log.h"

സ്ഥിതം പൂർണ്ണസംഖ്യ ngroups;
സ്ഥിതം അക്ഷരം **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
പൂർണ്ണസംഖ്യ
ga_init(സ്ഥിരം അക്ഷരം *user, gid_t base)
{
	gid_t *groups_bygid;
	പൂർണ്ണസംഖ്യ ongroups, i, j, retry = 0;
	ഘടന group *gr;

	എങ്കിൽ (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#എങ്കിൽ defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#endif

	groups_bygid = xcalloc(ngroups, വലുപ്പം(*groups_bygid));
	ആകുമ്പോൾ (getgrouplist(user, base, groups_bygid, &ngroups) == -1) {
		എങ്കിൽ (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (long)base);
			സ്വതന്ത്രം(groups_bygid);
			groups_bygid = ശൂന്യ;
			ngroups = 0;
			തിരികെ 0;
		}
		എങ്കിൽ (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (long)base,
			    (long)ongroups, (long)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    വലുപ്പം(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, വലുപ്പം(*groups_byname));

	വേണ്ടി (i = 0, j = 0; i < ngroups; i++)
		എങ്കിൽ ((gr = getgrgid(groups_bygid[i])) != ശൂന്യ)
			groups_byname[j++] = xstrdup(gr->gr_name);
	സ്വതന്ത്രം(groups_bygid);
	തിരികെ (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
പൂർണ്ണസംഖ്യ
ga_match(അക്ഷരം * സ്ഥിരം *groups, പൂർണ്ണസംഖ്യ n)
{
	പൂർണ്ണസംഖ്യ i, j;

	വേണ്ടി (i = 0; i < ngroups; i++)
		വേണ്ടി (j = 0; j < n; j++)
			എങ്കിൽ (match_pattern(groups_byname[i], groups[j]))
				തിരികെ 1;
	തിരികെ 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
പൂർണ്ണസംഖ്യ
ga_match_pattern_list(സ്ഥിരം അക്ഷരം *group_pattern)
{
	പൂർണ്ണസംഖ്യ i, found = 0;

	വേണ്ടി (i = 0; i < ngroups; i++) {
		തിരഞ്ഞെടുപ്പ് (match_usergroup_pattern_list(groups_byname[i],
		    group_pattern)) {
		അവസ്ഥ -1:
			തിരികെ 0;	/* Negated match wins */
		അവസ്ഥ 0:
			തുടരുക;
		അവസ്ഥ 1:
			found = 1;
		}
	}
	തിരികെ found;
}

/*
 * Free memory allocated for group access list.
 */
ശൂന്യം
ga_free(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (ngroups > 0) {
		വേണ്ടി (i = 0; i < ngroups; i++)
			സ്വതന്ത്രം(groups_byname[i]);
		ngroups = 0;
		സ്വതന്ത്രം(groups_byname);
		groups_byname = ശൂന്യ;
	}
}
