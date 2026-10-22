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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <grp.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "groupaccess.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "log.h"

स्थिर पूर्णांक ngroups;
स्थिर अक्षर **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
पूर्णांक
ga_init(स्थिरांक अक्षर *user, gid_t base)
{
	gid_t *groups_bygid;
	पूर्णांक ongroups, i, j, retry = 0;
	संरचना group *gr;

	जर (ngroups > 0)
		ga_free();

	ongroups = ngroups = NGROUPS_MAX;
#जर defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ongroups = ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#endif

	groups_bygid = xcalloc(ngroups, आकार(*groups_bygid));
	पर्यंत (getgrouplist(user, base, groups_bygid, &ngroups) == -1) {
		जर (ngroups <= ongroups) {
			error("getgrouplist(\"%s\", %ld): failed",
			    user, (दीर्घ)base);
			मुक्त(groups_bygid);
			groups_bygid = रिक्त;
			ngroups = 0;
			परत 0;
		}
		जर (retry++ > 0) {
			fatal("getgrouplist(\"%s\", %ld): groups list too big "
			    "(have %ld, need %ld)", user, (दीर्घ)base,
			    (दीर्घ)ongroups, (दीर्घ)ngroups);
		}
		groups_bygid = xreallocarray(groups_bygid, ngroups,
		    आकार(*groups_bygid));
	}
	groups_byname = xcalloc(ngroups, आकार(*groups_byname));

	साठी (i = 0, j = 0; i < ngroups; i++)
		जर ((gr = getgrgid(groups_bygid[i])) != रिक्त)
			groups_byname[j++] = xstrdup(gr->gr_name);
	मुक्त(groups_bygid);
	परत (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
पूर्णांक
ga_match(अक्षर * स्थिरांक *groups, पूर्णांक n)
{
	पूर्णांक i, j;

	साठी (i = 0; i < ngroups; i++)
		साठी (j = 0; j < n; j++)
			जर (match_pattern(groups_byname[i], groups[j]))
				परत 1;
	परत 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
पूर्णांक
ga_match_pattern_list(स्थिरांक अक्षर *group_pattern)
{
	पूर्णांक i, found = 0;

	साठी (i = 0; i < ngroups; i++) {
		निवड (match_usergroup_pattern_list(groups_byname[i],
		    group_pattern)) {
		स्थिती -1:
			परत 0;	/* Negated match wins */
		स्थिती 0:
			सुरूठेवा;
		स्थिती 1:
			found = 1;
		}
	}
	परत found;
}

/*
 * Free memory allocated for group access list.
 */
शून्य
ga_free(शून्य)
{
	पूर्णांक i;

	जर (ngroups > 0) {
		साठी (i = 0; i < ngroups; i++)
			मुक्त(groups_byname[i]);
		ngroups = 0;
		मुक्त(groups_byname);
		groups_byname = रिक्त;
	}
}
