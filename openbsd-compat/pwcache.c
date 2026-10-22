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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <grp.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */

#ifndef HAVE_USER_FROM_UID
எழுத்து *
user_from_uid(uid_t uid, முழு nouser)
{
	நிலையான கட்டமைப்பு ncache {
		uid_t	uid;
		எழுத்து	*name;
	} c_uid[NCACHE];
	நிலையான முழு pwopen;
	நிலையான எழுத்து nbuf[15];		/* 32 bits == 10 digits */
	கட்டமைப்பு passwd *pw;
	கட்டமைப்பு ncache *cp;

	cp = c_uid + (uid & MASK);
	எனில் (cp->uid != uid || cp->name == வெற்று) {
		எனில் (pwopen == 0) {
#ifdef HAVE_SETPASSENT
			setpassent(1);
#endif
			pwopen = 1;
		}
		எனில் ((pw = getpwuid(uid)) == வெற்று) {
			எனில் (nouser)
				திரும்பு (வெற்று);
			(வெறுமை)snprintf(nbuf, அளவு(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		எனில் (cp->name != வெற்று)
			விடுவி(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	திரும்பு (cp->name);
}
#endif

#ifndef HAVE_GROUP_FROM_GID
எழுத்து *
group_from_gid(gid_t gid, முழு nogroup)
{
	நிலையான கட்டமைப்பு ncache {
		gid_t	gid;
		எழுத்து	*name;
	} c_gid[NCACHE];
	நிலையான முழு gropen;
	நிலையான எழுத்து nbuf[15];		/* 32 bits == 10 digits */
	கட்டமைப்பு group *gr;
	கட்டமைப்பு ncache *cp;

	cp = c_gid + (gid & MASK);
	எனில் (cp->gid != gid || cp->name == வெற்று) {
		எனில் (gropen == 0) {
#ifdef HAVE_SETGROUPENT
			setgroupent(1);
#endif
			gropen = 1;
		}
		எனில் ((gr = getgrgid(gid)) == வெற்று) {
			எனில் (nogroup)
				திரும்பு (வெற்று);
			(வெறுமை)snprintf(nbuf, அளவு(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		எனில் (cp->name != வெற்று)
			விடுவி(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	திரும்பு (cp->name);
}
#endif
