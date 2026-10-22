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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <grp.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */

#ifndef HAVE_USER_FROM_UID
ৱর্ণ *
user_from_uid(uid_t uid, পূর্ণাঙ্ক nouser)
{
	স্থির সংরচনা ncache {
		uid_t	uid;
		ৱর্ণ	*name;
	} c_uid[NCACHE];
	স্থির পূর্ণাঙ্ক pwopen;
	স্থির ৱর্ণ nbuf[15];		/* 32 bits == 10 digits */
	সংরচনা passwd *pw;
	সংরচনা ncache *cp;

	cp = c_uid + (uid & MASK);
	যদি (cp->uid != uid || cp->name == রিক্ত) {
		যদি (pwopen == 0) {
#ifdef HAVE_SETPASSENT
			setpassent(1);
#endif
			pwopen = 1;
		}
		যদি ((pw = getpwuid(uid)) == রিক্ত) {
			যদি (nouser)
				ঘূৰাই (রিক্ত);
			(শূন্য)snprintf(nbuf, পরিমাণ(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		যদি (cp->name != রিক্ত)
			মুক্ত(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	ঘূৰাই (cp->name);
}
#endif

#ifndef HAVE_GROUP_FROM_GID
ৱর্ণ *
group_from_gid(gid_t gid, পূর্ণাঙ্ক nogroup)
{
	স্থির সংরচনা ncache {
		gid_t	gid;
		ৱর্ণ	*name;
	} c_gid[NCACHE];
	স্থির পূর্ণাঙ্ক gropen;
	স্থির ৱর্ণ nbuf[15];		/* 32 bits == 10 digits */
	সংরচনা group *gr;
	সংরচনা ncache *cp;

	cp = c_gid + (gid & MASK);
	যদি (cp->gid != gid || cp->name == রিক্ত) {
		যদি (gropen == 0) {
#ifdef HAVE_SETGROUPENT
			setgroupent(1);
#endif
			gropen = 1;
		}
		যদি ((gr = getgrgid(gid)) == রিক্ত) {
			যদি (nogroup)
				ঘূৰাই (রিক্ত);
			(শূন্য)snprintf(nbuf, পরিমাণ(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		যদি (cp->name != রিক্ত)
			মুক্ত(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	ঘূৰাই (cp->name);
}
#endif
