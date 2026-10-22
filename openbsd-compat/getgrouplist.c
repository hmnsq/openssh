/*	$OpenBSD: getgrouplist.c,v 1.12 2005/08/08 08:05:34 espie Exp */
/*
 * Copyright (c) 1991, 1993
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

/* OPENBSD ORIGINAL: lib/libc/gen/getgrouplist.c */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETGROUPLIST

/*
 * get credential
 */
#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <grp.h>

ಪೂರ್ಣಾಂಕ
getgrouplist(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *uname, gid_t agroup, gid_t *groups, ಪೂರ್ಣಾಂಕ *grpcnt)
{
	ರಚನೆ ಗುಂಪು *grp;
	ಪೂರ್ಣಾಂಕ i, ngroups;
	ಪೂರ್ಣಾಂಕ ret, maxgroups;
	ಪೂರ್ಣಾಂಕ bail;

	ret = 0;
	ngroups = 0;
	maxgroups = *grpcnt;

	/*
	 * install primary group
	 */
	ಆದರೆ (ngroups >= maxgroups) {
		*grpcnt = ngroups;
		ಹಿಂತಿರುಗಿ (-1);
	}
	groups[ngroups++] = agroup;

	/*
	 * Scan the group file to find additional groups.
	 */
	setgrent();
	ಆಗ ((grp = getgrent())) {
		ಆದರೆ (grp->gr_gid == agroup)
			ಮುಂದುವರಿ;
		ಗಾಗಿ (bail = 0, i = 0; bail == 0 && i < ngroups; i++)
			ಆದರೆ (groups[i] == grp->gr_gid)
				bail = 1;
		ಆದರೆ (bail)
			ಮುಂದುವರಿ;
		ಗಾಗಿ (i = 0; grp->gr_mem[i]; i++) {
			ಆದರೆ (!strcmp(grp->gr_mem[i], uname)) {
				ಆದರೆ (ngroups >= maxgroups) {
					ret = -1;
					ಹೋಗು ಹೊರಹೋಗು;
				}
				groups[ngroups++] = grp->gr_gid;
				ನಿಲ್ಲಿಸು;
			}
		}
	}
ಹೊರಹೋಗು:
	endgrent();
	*grpcnt = ngroups;
	ಹಿಂತಿರುಗಿ (ret);
}

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_GETGROUPLIST */
