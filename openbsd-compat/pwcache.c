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

#ವ್ಯಾಖ್ಯಾನಿಸು	NCACHE	64			/* power of 2 */
#ವ್ಯಾಖ್ಯಾನಿಸು	ಮುಖವಾಡ_2	(NCACHE - 1)		/* bits to store with */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_USER_FROM_UID
ಅಕ್ಷರ *
user_from_uid(uid_t uid, ಪೂರ್ಣಾಂಕ nouser)
{
	ಸ್ಥಿರ ರಚನೆ ncache {
		uid_t	uid;
		ಅಕ್ಷರ	*name;
	} c_uid[NCACHE];
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ pwopen;
	ಸ್ಥಿರ ಅಕ್ಷರ nbuf[15];		/* 32 bits == 10 digits */
	ರಚನೆ passwd *pw;
	ರಚನೆ ncache *cp;

	cp = c_uid + (uid & ಮುಖವಾಡ_2);
	ಆದರೆ (cp->uid != uid || cp->name == ಖಾಲಿ) {
		ಆದರೆ (pwopen == 0) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SETPASSENT
			setpassent(1);
#ಆದರೆ_ಅಂತ್ಯ
			pwopen = 1;
		}
		ಆದರೆ ((pw = getpwuid(uid)) == ಖಾಲಿ) {
			ಆದರೆ (nouser)
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			(ಶೂನ್ಯ)snprintf(nbuf, ಗಾತ್ರ(nbuf), "%lu", (u_long)uid);
		}
		cp->uid = uid;
		ಆದರೆ (cp->name != ಖಾಲಿ)
			ಬಿಡುಗಡೆ(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	ಹಿಂತಿರುಗಿ (cp->name);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ಗುಂಪು_FROM_GID
ಅಕ್ಷರ *
ಗುಂಪು_from_gid(gid_t gid, ಪೂರ್ಣಾಂಕ nogroup)
{
	ಸ್ಥಿರ ರಚನೆ ncache {
		gid_t	gid;
		ಅಕ್ಷರ	*name;
	} c_gid[NCACHE];
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ gropen;
	ಸ್ಥಿರ ಅಕ್ಷರ nbuf[15];		/* 32 bits == 10 digits */
	ರಚನೆ ಗುಂಪು *gr;
	ರಚನೆ ncache *cp;

	cp = c_gid + (gid & ಮುಖವಾಡ_2);
	ಆದರೆ (cp->gid != gid || cp->name == ಖಾಲಿ) {
		ಆದರೆ (gropen == 0) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SETGROUPENT
			setgroupent(1);
#ಆದರೆ_ಅಂತ್ಯ
			gropen = 1;
		}
		ಆದರೆ ((gr = getgrgid(gid)) == ಖಾಲಿ) {
			ಆದರೆ (nogroup)
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			(ಶೂನ್ಯ)snprintf(nbuf, ಗಾತ್ರ(nbuf), "%lu", (u_long)gid);
		}
		cp->gid = gid;
		ಆದರೆ (cp->name != ಖಾಲಿ)
			ಬಿಡುಗಡೆ(cp->name);
		cp->name = strdup(gr ? gr->gr_name : nbuf);
	}
	ಹಿಂತಿರುಗಿ (cp->name);
}
#ಆದರೆ_ಅಂತ್ಯ
