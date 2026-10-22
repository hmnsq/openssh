/*	$OpenBSD: pwcache.c,v 1.9 2005/08/08 08:05:34 espie Exp $ */
/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/gen/pwcache.c */

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <grp.h>
#समावेश <pwd.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#घोषणा	NCACHE	64			/* power of 2 */
#घोषणा	MASK	(NCACHE - 1)		/* bits to store with */

#अगर_अघोषित HAVE_USER_FROM_UID
अक्षर *
user_from_uid(uid_t uid, पूर्णांक nouser)
{
	अटल काष्ठा ncache {
		uid_t	uid;
		अक्षर	*name;
	} c_uid[NCACHE];
	अटल पूर्णांक pwopen;
	अटल अक्षर nbuf[15];		/* 32 bits == 10 digits */
	काष्ठा passwd *pw;
	काष्ठा ncache *cp;

	cp = c_uid + (uid & MASK);
	अगर (cp->uid != uid || cp->name == शून्य) {
		अगर (pwopen == 0) {
#अगर_घोषित HAVE_SETPASSENT
			setpassent(1);
#पूर्ण_अगर
			pwopen = 1;
		}
		अगर ((pw = getpwuid(uid)) == शून्य) {
			अगर (nouser)
				वापस (शून्य);
			(व्योम)snprintf(nbuf, माप(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		अगर (cp->name != शून्य)
			मुक्त(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	वापस (cp->name);
}
#पूर्ण_अगर

#अगर_अघोषित HAVE_GROUP_FROM_GID
अक्षर *
group_from_gid(gid_t gid, पूर्णांक nogroup)
{
	अटल काष्ठा ncache {
		gid_t	gid;
		अक्षर	*name;
	} c_gid[NCACHE];
	अटल पूर्णांक gropen;
	अटल अक्षर nbuf[15];		/* 32 bits == 10 digits */
	काष्ठा group *gr;
	काष्ठा ncache *cp;

	cp = c_gid + (gid & MASK);
	अगर (cp->gid != gid || cp->name == शून्य) {
		अगर (gropen == 0) {
#अगर_घोषित HAVE_SETGROUPENT
			setgroupent(1);
#पूर्ण_अगर
			gropen = 1;
		}
		अगर ((gr = getgrgid(gid)) == शून्य) {
			अगर (nogroup)
				वापस (शून्य);
			(व्योम)snprintf(nbuf, माप(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		अगर (cp->name != शून्य)
			मुक्त(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	वापस (cp->name);
}
#पूर्ण_अगर
