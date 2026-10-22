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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <grp.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "groupaccess.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "log.h"

நிலையான முழு ngroups;
நிலையான எழுத்து **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
முழு
ga_init(மாறிலி எழுத்து *user, gid_t base)
{
	gid_t *groups_bygid;
	முழு ongroups, i, j, retry = 0;
	கட்டமைப்பு group *gr;

	எனில் (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#எனில் defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#endif

	groups_bygid = xcalloc(ngroups, அளவு(*groups_bygid));
	போது (getgrouplist(user, base, groups_bygid, &ngroups) == -1) {
		எனில் (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (long)base);
			விடுவி(groups_bygid);
			groups_bygid = வெற்று;
			ngroups = 0;
			திரும்பு 0;
		}
		எனில் (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (long)base,
			    (long)ongroups, (long)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    அளவு(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, அளவு(*groups_byname));

	க்கு (i = 0, j = 0; i < ngroups; i++)
		எனில் ((gr = getgrgid(groups_bygid[i])) != வெற்று)
			groups_byname[j++] = xstrdup(gr->gr_name);
	விடுவி(groups_bygid);
	திரும்பு (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
முழு
ga_match(எழுத்து * மாறிலி *groups, முழு n)
{
	முழு i, j;

	க்கு (i = 0; i < ngroups; i++)
		க்கு (j = 0; j < n; j++)
			எனில் (match_pattern(groups_byname[i], groups[j]))
				திரும்பு 1;
	திரும்பு 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
முழு
ga_match_pattern_list(மாறிலி எழுத்து *group_pattern)
{
	முழு i, found = 0;

	க்கு (i = 0; i < ngroups; i++) {
		தேர்வு (match_usergroup_pattern_list(groups_byname[i],
		    group_pattern)) {
		நிலை -1:
			திரும்பு 0;	/* Negated match wins */
		நிலை 0:
			தொடர்;
		நிலை 1:
			found = 1;
		}
	}
	திரும்பு found;
}

/*
 * Free memory allocated for group access list.
 */
வெறுமை
ga_free(வெறுமை)
{
	முழு i;

	எனில் (ngroups > 0) {
		க்கு (i = 0; i < ngroups; i++)
			விடுவி(groups_byname[i]);
		ngroups = 0;
		விடுவி(groups_byname);
		groups_byname = வெற்று;
	}
}
