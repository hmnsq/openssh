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

#تعریف_کرو	NCACHE	64			/* power of 2 */
#تعریف_کرو	نقاب_2	(NCACHE - 1)		/* bits to store with */

#اگر_غیر_تعریف_شدہ HAVE_USER_FROM_UID
حرف *
user_from_uid(uid_t uid, صحیح nouser)
{
	ساکن ساخت ncache {
		uid_t	uid;
		حرف	*name;
	} c_uid[NCACHE];
	ساکن صحیح pwopen;
	ساکن حرف nbuf[15];		/* 32 bits == 10 digits */
	ساخت passwd *pw;
	ساخت ncache *cp;

	cp = c_uid + (uid & نقاب_2);
	اگر (cp->uid != uid || cp->name == تہی) {
		اگر (pwopen == 0) {
#اگر_تعریف_شدہ HAVE_SETPASSENT
			setpassent(1);
#اگر_ختم
			pwopen = 1;
		}
		اگر ((pw = getpwuid(uid)) == تہی) {
			اگر (nouser)
				واپس (تہی);
			(خالی)snprintf(nbuf, حجم(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		اگر (cp->name != تہی)
			آزاد(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	واپس (cp->name);
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_گروہ_FROM_GID
حرف *
گروہ_from_gid(gid_t gid, صحیح nogroup)
{
	ساکن ساخت ncache {
		gid_t	gid;
		حرف	*name;
	} c_gid[NCACHE];
	ساکن صحیح gropen;
	ساکن حرف nbuf[15];		/* 32 bits == 10 digits */
	ساخت گروہ *gr;
	ساخت ncache *cp;

	cp = c_gid + (gid & نقاب_2);
	اگر (cp->gid != gid || cp->name == تہی) {
		اگر (gropen == 0) {
#اگر_تعریف_شدہ HAVE_SETGROUPENT
			setgroupent(1);
#اگر_ختم
			gropen = 1;
		}
		اگر ((gr = getgrgid(gid)) == تہی) {
			اگر (nogroup)
				واپس (تہی);
			(خالی)snprintf(nbuf, حجم(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		اگر (cp->name != تہی)
			آزاد(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	واپس (cp->name);
}
#اگر_ختم
