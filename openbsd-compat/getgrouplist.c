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

#অন্তর্ভাব "includes.h"

#ifndef HAVE_GETGROUPLIST

/*
 * get credential
 */
#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <grp.h>

পূর্ণসংখ্যা
getgrouplist(ধ্রুবক অক্ষর *uname, gid_t agroup, gid_t *groups, পূর্ণসংখ্যা *grpcnt)
{
	কাঠামো group *grp;
	পূর্ণসংখ্যা i, ngroups;
	পূর্ণসংখ্যা ret, maxgroups;
	পূর্ণসংখ্যা bail;

	ret = 0;
	ngroups = 0;
	maxgroups = *grpcnt;

	/*
	 * install primary group
	 */
	যদি (ngroups >= maxgroups) {
		*grpcnt = ngroups;
		ফেরত (-1);
	}
	groups[ngroups++] = agroup;

	/*
	 * Scan the group file to find additional groups.
	 */
	setgrent();
	যখন ((grp = getgrent())) {
		যদি (grp->gr_gid == agroup)
			চালু;
		জন্য (bail = 0, i = 0; bail == 0 && i < ngroups; i++)
			যদি (groups[i] == grp->gr_gid)
				bail = 1;
		যদি (bail)
			চালু;
		জন্য (i = 0; grp->gr_mem[i]; i++) {
			যদি (!strcmp(grp->gr_mem[i], uname)) {
				যদি (ngroups >= maxgroups) {
					ret = -1;
					যাও out;
				}
				groups[ngroups++] = grp->gr_gid;
				বিরতি;
			}
		}
	}
out:
	endgrent();
	*grpcnt = ngroups;
	ফেরত (ret);
}

#endif /* HAVE_GETGROUPLIST */
