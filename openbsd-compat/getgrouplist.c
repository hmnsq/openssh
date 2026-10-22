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

#அந்தர்பாவ "includes.h"

#ifndef HAVE_GETGROUPLIST

/*
 * get credential
 */
#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <grp.h>

முழு
getgrouplist(மாறிலி எழுத்து *uname, gid_t agroup, gid_t *groups, முழு *grpcnt)
{
	கட்டமைப்பு group *grp;
	முழு i, ngroups;
	முழு ret, maxgroups;
	முழு bail;

	ret = 0;
	ngroups = 0;
	maxgroups = *grpcnt;

	/*
	 * install primary group
	 */
	எனில் (ngroups >= maxgroups) {
		*grpcnt = ngroups;
		திரும்பு (-1);
	}
	groups[ngroups++] = agroup;

	/*
	 * Scan the group file to find additional groups.
	 */
	setgrent();
	போது ((grp = getgrent())) {
		எனில் (grp->gr_gid == agroup)
			தொடர்;
		க்கு (bail = 0, i = 0; bail == 0 && i < ngroups; i++)
			எனில் (groups[i] == grp->gr_gid)
				bail = 1;
		எனில் (bail)
			தொடர்;
		க்கு (i = 0; grp->gr_mem[i]; i++) {
			எனில் (!strcmp(grp->gr_mem[i], uname)) {
				எனில் (ngroups >= maxgroups) {
					ret = -1;
					செல் out;
				}
				groups[ngroups++] = grp->gr_gid;
				நிறுத்து;
			}
		}
	}
out:
	endgrent();
	*grpcnt = ngroups;
	திரும்பு (ret);
}

#endif /* HAVE_GETGROUPLIST */
