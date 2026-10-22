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

#include "includes.h"

#include <sys/types.h>

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */

#ifndef HAVE_USER_FROM_UID
var_na *
user_from_uid(uid_t uid, ကိန်းပြည့် nouser)
{
	static sa_nracanaa ncache {
		uid_t	uid;
		var_na	*name;
	} c_uid[NCACHE];
	static ကိန်းပြည့် pwopen;
	static var_na nbuf[15];		/* 32 bits == 10 digits */
	sa_nracanaa passwd *pw;
	sa_nracanaa ncache *cp;

	cp = c_uid + (uid & MASK);
	အကယ်၍ (cp->uid != uid || cp->name == NULL) {
		အကယ်၍ (pwopen == 0) {
#ifdef HAVE_SETPASSENT
			setpassent(1);
#endif
			pwopen = 1;
		}
		အကယ်၍ ((pw = getpwuid(uid)) == NULL) {
			အကယ်၍ (nouser)
				ပြန်ပေး (NULL);
			(void)snprintf(nbuf, parimaa_na(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		အကယ်၍ (cp->name != NULL)
			free(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	ပြန်ပေး (cp->name);
}
#endif

#ifndef HAVE_GROUP_FROM_GID
var_na *
group_from_gid(gid_t gid, ကိန်းပြည့် nogroup)
{
	static sa_nracanaa ncache {
		gid_t	gid;
		var_na	*name;
	} c_gid[NCACHE];
	static ကိန်းပြည့် gropen;
	static var_na nbuf[15];		/* 32 bits == 10 digits */
	sa_nracanaa group *gr;
	sa_nracanaa ncache *cp;

	cp = c_gid + (gid & MASK);
	အကယ်၍ (cp->gid != gid || cp->name == NULL) {
		အကယ်၍ (gropen == 0) {
#ifdef HAVE_SETGROUPENT
			setgroupent(1);
#endif
			gropen = 1;
		}
		အကယ်၍ ((gr = getgrgid(gid)) == NULL) {
			အကယ်၍ (nogroup)
				ပြန်ပေး (NULL);
			(void)snprintf(nbuf, parimaa_na(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		အကယ်၍ (cp->name != NULL)
			free(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	ပြန်ပေး (cp->name);
}
#endif
