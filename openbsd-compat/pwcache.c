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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <grp.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */

#ifndef HAVE_USER_FROM_UID
वर्ण *
user_from_uid(uid_t uid, पूर्णाङ्क nouser)
{
	स्थिर संरचना ncache {
		uid_t	uid;
		वर्ण	*name;
	} c_uid[NCACHE];
	स्थिर पूर्णाङ्क pwopen;
	स्थिर वर्ण nbuf[15];		/* 32 bits == 10 digits */
	संरचना passwd *pw;
	संरचना ncache *cp;

	cp = c_uid + (uid & MASK);
	यदि (cp->uid != uid || cp->name == रिक्त) {
		यदि (pwopen == 0) {
#ifdef HAVE_SETPASSENT
			setpassent(1);
#endif
			pwopen = 1;
		}
		यदि ((pw = getpwuid(uid)) == रिक्त) {
			यदि (nouser)
				प्रत्यागम (रिक्त);
			(शून्य)snprintf(nbuf, परिमाण(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		यदि (cp->name != रिक्त)
			मुक्त(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	प्रत्यागम (cp->name);
}
#endif

#ifndef HAVE_GROUP_FROM_GID
वर्ण *
group_from_gid(gid_t gid, पूर्णाङ्क nogroup)
{
	स्थिर संरचना ncache {
		gid_t	gid;
		वर्ण	*name;
	} c_gid[NCACHE];
	स्थिर पूर्णाङ्क gropen;
	स्थिर वर्ण nbuf[15];		/* 32 bits == 10 digits */
	संरचना group *gr;
	संरचना ncache *cp;

	cp = c_gid + (gid & MASK);
	यदि (cp->gid != gid || cp->name == रिक्त) {
		यदि (gropen == 0) {
#ifdef HAVE_SETGROUPENT
			setgroupent(1);
#endif
			gropen = 1;
		}
		यदि ((gr = getgrgid(gid)) == रिक्त) {
			यदि (nogroup)
				प्रत्यागम (रिक्त);
			(शून्य)snprintf(nbuf, परिमाण(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		यदि (cp->name != रिक्त)
			मुक्त(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	प्रत्यागम (cp->name);
}
#endif
