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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <grp.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */

#ifndef HAVE_USER_FROM_UID
અક્ષર *
user_from_uid(uid_t uid, પૂર્ણાંક nouser)
{
	સ્થિર સંરચના ncache {
		uid_t	uid;
		અક્ષર	*name;
	} c_uid[NCACHE];
	સ્થિર પૂર્ણાંક pwopen;
	સ્થિર અક્ષર nbuf[15];		/* 32 bits == 10 digits */
	સંરચના passwd *pw;
	સંરચના ncache *cp;

	cp = c_uid + (uid & MASK);
	જો (cp->uid != uid || cp->name == ખાલી) {
		જો (pwopen == 0) {
#ifdef HAVE_SETPASSENT
			setpassent(1);
#endif
			pwopen = 1;
		}
		જો ((pw = getpwuid(uid)) == ખાલી) {
			જો (nouser)
				પાછા (ખાલી);
			(શૂન્ય)snprintf(nbuf, કદ(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		જો (cp->name != ખાલી)
			મુક્ત(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	પાછા (cp->name);
}
#endif

#ifndef HAVE_GROUP_FROM_GID
અક્ષર *
group_from_gid(gid_t gid, પૂર્ણાંક nogroup)
{
	સ્થિર સંરચના ncache {
		gid_t	gid;
		અક્ષર	*name;
	} c_gid[NCACHE];
	સ્થિર પૂર્ણાંક gropen;
	સ્થિર અક્ષર nbuf[15];		/* 32 bits == 10 digits */
	સંરચના group *gr;
	સંરચના ncache *cp;

	cp = c_gid + (gid & MASK);
	જો (cp->gid != gid || cp->name == ખાલી) {
		જો (gropen == 0) {
#ifdef HAVE_SETGROUPENT
			setgroupent(1);
#endif
			gropen = 1;
		}
		જો ((gr = getgrgid(gid)) == ખાલી) {
			જો (nogroup)
				પાછા (ખાલી);
			(શૂન્ય)snprintf(nbuf, કદ(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		જો (cp->name != ખાલી)
			મુક્ત(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	પાછા (cp->name);
}
#endif
