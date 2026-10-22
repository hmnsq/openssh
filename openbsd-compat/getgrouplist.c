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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETGROUPLIST

/*
 * get credential
 */
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <grp.h>

ਪੂਰਨ
getgrouplist(ਅਚਲ ਅੱਖਰ *uname, gid_t agroup, gid_t *groups, ਪੂਰਨ *grpcnt)
{
	ਬਣਤਰ ਸਮੂਹ *grp;
	ਪੂਰਨ i, ngroups;
	ਪੂਰਨ ret, maxgroups;
	ਪੂਰਨ bail;

	ret = 0;
	ngroups = 0;
	maxgroups = *grpcnt;

	/*
	 * install primary group
	 */
	ਜੇ (ngroups >= maxgroups) {
		*grpcnt = ngroups;
		ਵਾਪਸ (-1);
	}
	groups[ngroups++] = agroup;

	/*
	 * Scan the group file to find additional groups.
	 */
	setgrent();
	ਜਦੋਂ ((grp = getgrent())) {
		ਜੇ (grp->gr_gid == agroup)
			ਜਾਰੀ;
		ਲਈ (bail = 0, i = 0; bail == 0 && i < ngroups; i++)
			ਜੇ (groups[i] == grp->gr_gid)
				bail = 1;
		ਜੇ (bail)
			ਜਾਰੀ;
		ਲਈ (i = 0; grp->gr_mem[i]; i++) {
			ਜੇ (!strcmp(grp->gr_mem[i], uname)) {
				ਜੇ (ngroups >= maxgroups) {
					ret = -1;
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				groups[ngroups++] = grp->gr_gid;
				ਰੋਕੋ;
			}
		}
	}
ਬਾਹਰਲਾ:
	endgrent();
	*grpcnt = ngroups;
	ਵਾਪਸ (ret);
}

#ਜੇ_ਅੰਤ /* HAVE_GETGROUPLIST */
