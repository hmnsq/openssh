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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	NCACHE	64			/* power of 2 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	ਨਕਾਬ_2	(NCACHE - 1)		/* bits to store with */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_USER_FROM_UID
ਅੱਖਰ *
user_from_uid(uid_t uid, ਪੂਰਨ nouser)
{
	ਸਥਿਰ ਬਣਤਰ ncache {
		uid_t	uid;
		ਅੱਖਰ	*name;
	} c_uid[NCACHE];
	ਸਥਿਰ ਪੂਰਨ pwopen;
	ਸਥਿਰ ਅੱਖਰ nbuf[15];		/* 32 bits == 10 digits */
	ਬਣਤਰ passwd *pw;
	ਬਣਤਰ ncache *cp;

	cp = c_uid + (uid & ਨਕਾਬ_2);
	ਜੇ (cp->uid != uid || cp->name == ਨਿਰਾ) {
		ਜੇ (pwopen == 0) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SETPASSENT
			setpassent(1);
#ਜੇ_ਅੰਤ
			pwopen = 1;
		}
		ਜੇ ((pw = getpwuid(uid)) == ਨਿਰਾ) {
			ਜੇ (nouser)
				ਵਾਪਸ (ਨਿਰਾ);
			(ਖਾਲੀ)snprintf(nbuf, ਆਕਾਰ(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		ਜੇ (cp->name != ਨਿਰਾ)
			ਮੁਕਤ(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	ਵਾਪਸ (cp->name);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_ਸਮੂਹ_FROM_GID
ਅੱਖਰ *
ਸਮੂਹ_from_gid(gid_t gid, ਪੂਰਨ nogroup)
{
	ਸਥਿਰ ਬਣਤਰ ncache {
		gid_t	gid;
		ਅੱਖਰ	*name;
	} c_gid[NCACHE];
	ਸਥਿਰ ਪੂਰਨ gropen;
	ਸਥਿਰ ਅੱਖਰ nbuf[15];		/* 32 bits == 10 digits */
	ਬਣਤਰ ਸਮੂਹ *gr;
	ਬਣਤਰ ncache *cp;

	cp = c_gid + (gid & ਨਕਾਬ_2);
	ਜੇ (cp->gid != gid || cp->name == ਨਿਰਾ) {
		ਜੇ (gropen == 0) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SETGROUPENT
			setgroupent(1);
#ਜੇ_ਅੰਤ
			gropen = 1;
		}
		ਜੇ ((gr = getgrgid(gid)) == ਨਿਰਾ) {
			ਜੇ (nogroup)
				ਵਾਪਸ (ਨਿਰਾ);
			(ਖਾਲੀ)snprintf(nbuf, ਆਕਾਰ(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		ਜੇ (cp->name != ਨਿਰਾ)
			ਮੁਕਤ(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	ਵਾਪਸ (cp->name);
}
#ਜੇ_ਅੰਤ
