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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <grp.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */

#ifndef HAVE_USER_FROM_UID
ଅକ୍ଷର *
user_from_uid(uid_t uid, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nouser)
{
	ସ୍ଥିର ସଂରଚନା ncache {
		uid_t	uid;
		ଅକ୍ଷର	*name;
	} c_uid[NCACHE];
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା pwopen;
	ସ୍ଥିର ଅକ୍ଷର nbuf[15];		/* 32 bits == 10 digits */
	ସଂରଚନା passwd *pw;
	ସଂରଚନା ncache *cp;

	cp = c_uid + (uid & MASK);
	ଯଦି (cp->uid != uid || cp->name == ଖାଲି) {
		ଯଦି (pwopen == 0) {
#ifdef HAVE_SETPASSENT
			setpassent(1);
#endif
			pwopen = 1;
		}
		ଯଦି ((pw = getpwuid(uid)) == ଖାଲି) {
			ଯଦି (nouser)
				ଫେରନ୍ତୁ (ଖାଲି);
			(ଶୂନ୍ୟ)snprintf(nbuf, ଆକାର(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		ଯଦି (cp->name != ଖାଲି)
			ମୁକ୍ତ(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	ଫେରନ୍ତୁ (cp->name);
}
#endif

#ifndef HAVE_GROUP_FROM_GID
ଅକ୍ଷର *
group_from_gid(gid_t gid, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nogroup)
{
	ସ୍ଥିର ସଂରଚନା ncache {
		gid_t	gid;
		ଅକ୍ଷର	*name;
	} c_gid[NCACHE];
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା gropen;
	ସ୍ଥିର ଅକ୍ଷର nbuf[15];		/* 32 bits == 10 digits */
	ସଂରଚନା group *gr;
	ସଂରଚନା ncache *cp;

	cp = c_gid + (gid & MASK);
	ଯଦି (cp->gid != gid || cp->name == ଖାଲି) {
		ଯଦି (gropen == 0) {
#ifdef HAVE_SETGROUPENT
			setgroupent(1);
#endif
			gropen = 1;
		}
		ଯଦି ((gr = getgrgid(gid)) == ଖାଲି) {
			ଯଦି (nogroup)
				ଫେରନ୍ତୁ (ଖାଲି);
			(ଶୂନ୍ୟ)snprintf(nbuf, ଆକାର(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		ଯଦି (cp->name != ଖାଲି)
			ମୁକ୍ତ(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	ଫେରନ୍ତୁ (cp->name);
}
#endif
