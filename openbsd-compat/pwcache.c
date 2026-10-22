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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <grp.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#నిర్వచించు	NCACHE	64			/* power of 2 */
#నిర్వచించు	ముసుగు_2	(NCACHE - 1)		/* bits to store with */

#నిర్వచితం_కాకపోతే HAVE_USER_FROM_UID
అక్షరం *
user_from_uid(uid_t uid, పూర్ణాంకం nouser)
{
	స్థిర నిర్మాణం ncache {
		uid_t	uid;
		అక్షరం	*name;
	} c_uid[NCACHE];
	స్థిర పూర్ణాంకం pwopen;
	స్థిర అక్షరం nbuf[15];		/* 32 bits == 10 digits */
	నిర్మాణం passwd *pw;
	నిర్మాణం ncache *cp;

	cp = c_uid + (uid & ముసుగు_2);
	ఒకవేళ (cp->uid != uid || cp->name == ఖాళీ) {
		ఒకవేళ (pwopen == 0) {
#నిర్వచితమైతే HAVE_SETPASSENT
			setpassent(1);
#అయితే_ముగింపు
			pwopen = 1;
		}
		ఒకవేళ ((pw = getpwuid(uid)) == ఖాళీ) {
			ఒకవేళ (nouser)
				తిరిగి (ఖాళీ);
			(శూన్య)snprintf(nbuf, పరిమాణం(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		ఒకవేళ (cp->name != ఖాళీ)
			విడుదల(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	తిరిగి (cp->name);
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_సమూహం_FROM_GID
అక్షరం *
సమూహం_from_gid(gid_t gid, పూర్ణాంకం nogroup)
{
	స్థిర నిర్మాణం ncache {
		gid_t	gid;
		అక్షరం	*name;
	} c_gid[NCACHE];
	స్థిర పూర్ణాంకం gropen;
	స్థిర అక్షరం nbuf[15];		/* 32 bits == 10 digits */
	నిర్మాణం సమూహం *gr;
	నిర్మాణం ncache *cp;

	cp = c_gid + (gid & ముసుగు_2);
	ఒకవేళ (cp->gid != gid || cp->name == ఖాళీ) {
		ఒకవేళ (gropen == 0) {
#నిర్వచితమైతే HAVE_SETGROUPENT
			setgroupent(1);
#అయితే_ముగింపు
			gropen = 1;
		}
		ఒకవేళ ((gr = getgrgid(gid)) == ఖాళీ) {
			ఒకవేళ (nogroup)
				తిరిగి (ఖాళీ);
			(శూన్య)snprintf(nbuf, పరిమాణం(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		ఒకవేళ (cp->name != ఖాళీ)
			విడుదల(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	తిరిగి (cp->name);
}
#అయితే_ముగింపు
