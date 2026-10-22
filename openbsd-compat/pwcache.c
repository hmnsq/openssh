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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <grp.h>
#شامل <pwd.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */

#ifndef HAVE_USER_FROM_UID
نویسه *
user_from_uid(uid_t uid, صحیح nouser)
{
	ایستا ساختار ncache {
		uid_t	uid;
		نویسه	*name;
	} c_uid[NCACHE];
	ایستا صحیح pwopen;
	ایستا نویسه nbuf[15];		/* 32 bits == 10 digits */
	ساختار passwd *pw;
	ساختار ncache *cp;

	cp = c_uid + (uid & MASK);
	اگر (cp->uid != uid || cp->name == پوچ) {
		اگر (pwopen == 0) {
#ifdef HAVE_SETPASSENT
			setpassent(1);
#endif
			pwopen = 1;
		}
		اگر ((pw = getpwuid(uid)) == پوچ) {
			اگر (nouser)
				بازگشت (پوچ);
			(تهی)snprintf(nbuf, اندازه(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		اگر (cp->name != پوچ)
			آزاد(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	بازگشت (cp->name);
}
#endif

#ifndef HAVE_GROUP_FROM_GID
نویسه *
group_from_gid(gid_t gid, صحیح nogroup)
{
	ایستا ساختار ncache {
		gid_t	gid;
		نویسه	*name;
	} c_gid[NCACHE];
	ایستا صحیح gropen;
	ایستا نویسه nbuf[15];		/* 32 bits == 10 digits */
	ساختار group *gr;
	ساختار ncache *cp;

	cp = c_gid + (gid & MASK);
	اگر (cp->gid != gid || cp->name == پوچ) {
		اگر (gropen == 0) {
#ifdef HAVE_SETGROUPENT
			setgroupent(1);
#endif
			gropen = 1;
		}
		اگر ((gr = getgrgid(gid)) == پوچ) {
			اگر (nogroup)
				بازگشت (پوچ);
			(تهی)snprintf(nbuf, اندازه(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		اگر (cp->name != پوچ)
			آزاد(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	بازگشت (cp->name);
}
#endif
