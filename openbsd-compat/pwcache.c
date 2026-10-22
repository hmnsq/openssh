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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <grp.h>
#ضمن <pwd.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#وصف_ڪريو	NCACHE	64			/* power of 2 */
#وصف_ڪريو	نقاب_2	(NCACHE - 1)		/* bits to store with */

#جيڪڏهن_وصف_نه_ٿيل HAVE_USER_FROM_UID
حرف *
user_from_uid(uid_t uid, صحيح nouser)
{
	ساكن بنية ncache {
		uid_t	uid;
		حرف	*name;
	} c_uid[NCACHE];
	ساكن صحيح pwopen;
	ساكن حرف nbuf[15];		/* 32 bits == 10 digits */
	بنية passwd *pw;
	بنية ncache *cp;

	cp = c_uid + (uid & نقاب_2);
	إذا (cp->uid != uid || cp->name == عدم) {
		إذا (pwopen == 0) {
#جيڪڏهن_وصف_ٿيل HAVE_SETPASSENT
			setpassent(1);
#جيڪڏهن_پورو
			pwopen = 1;
		}
		إذا ((pw = getpwuid(uid)) == عدم) {
			إذا (nouser)
				أرجع (عدم);
			(فراغ)snprintf(nbuf, حجم(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		إذا (cp->name != عدم)
			حرر(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	أرجع (cp->name);
}
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_گروهه_FROM_GID
حرف *
گروهه_from_gid(gid_t gid, صحيح nogroup)
{
	ساكن بنية ncache {
		gid_t	gid;
		حرف	*name;
	} c_gid[NCACHE];
	ساكن صحيح gropen;
	ساكن حرف nbuf[15];		/* 32 bits == 10 digits */
	بنية گروهه *gr;
	بنية ncache *cp;

	cp = c_gid + (gid & نقاب_2);
	إذا (cp->gid != gid || cp->name == عدم) {
		إذا (gropen == 0) {
#جيڪڏهن_وصف_ٿيل HAVE_SETGROUPENT
			setgroupent(1);
#جيڪڏهن_پورو
			gropen = 1;
		}
		إذا ((gr = getgrgid(gid)) == عدم) {
			إذا (nogroup)
				أرجع (عدم);
			(فراغ)snprintf(nbuf, حجم(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		إذا (cp->name != عدم)
			حرر(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	أرجع (cp->name);
}
#جيڪڏهن_پورو
