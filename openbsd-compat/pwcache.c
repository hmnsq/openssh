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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <grp.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */

#ifndef HAVE_USER_FROM_UID
ವರ್ಣ *
user_from_uid(uid_t uid, ಪೂರ್ಣಾಙ್ಕ nouser)
{
	ಸ್ಥಿರ ಸಂರಚನಾ ncache {
		uid_t	uid;
		ವರ್ಣ	*name;
	} c_uid[NCACHE];
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ pwopen;
	ಸ್ಥಿರ ವರ್ಣ nbuf[15];		/* 32 bits == 10 digits */
	ಸಂರಚನಾ passwd *pw;
	ಸಂರಚನಾ ncache *cp;

	cp = c_uid + (uid & MASK);
	ಯದಿ (cp->uid != uid || cp->name == ರಿಕ್ತ) {
		ಯದಿ (pwopen == 0) {
#ifdef HAVE_SETPASSENT
			setpassent(1);
#endif
			pwopen = 1;
		}
		ಯದಿ ((pw = getpwuid(uid)) == ರಿಕ್ತ) {
			ಯದಿ (nouser)
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			(ಶೂನ್ಯ)snprintf(nbuf, ಪರಿಮಾಣ(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		ಯದಿ (cp->name != ರಿಕ್ತ)
			ಮುಕ್ತ(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	ಪ್ರತ್ಯಾಗಮ (cp->name);
}
#endif

#ifndef HAVE_GROUP_FROM_GID
ವರ್ಣ *
group_from_gid(gid_t gid, ಪೂರ್ಣಾಙ್ಕ nogroup)
{
	ಸ್ಥಿರ ಸಂರಚನಾ ncache {
		gid_t	gid;
		ವರ್ಣ	*name;
	} c_gid[NCACHE];
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ gropen;
	ಸ್ಥಿರ ವರ್ಣ nbuf[15];		/* 32 bits == 10 digits */
	ಸಂರಚನಾ group *gr;
	ಸಂರಚನಾ ncache *cp;

	cp = c_gid + (gid & MASK);
	ಯದಿ (cp->gid != gid || cp->name == ರಿಕ್ತ) {
		ಯದಿ (gropen == 0) {
#ifdef HAVE_SETGROUPENT
			setgroupent(1);
#endif
			gropen = 1;
		}
		ಯದಿ ((gr = getgrgid(gid)) == ರಿಕ್ತ) {
			ಯದಿ (nogroup)
				ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
			(ಶೂನ್ಯ)snprintf(nbuf, ಪರಿಮಾಣ(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		ಯದಿ (cp->name != ರಿಕ್ತ)
			ಮುಕ್ತ(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	ಪ್ರತ್ಯಾಗಮ (cp->name);
}
#endif
