/*
 * Copyright (c) 2012 Darren Tucker (dtucker at zip com au).
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "log.h"

#ఒకవేళ !defined(HAVE_SETRESGID) || defined(BROKEN_SETRESGID)
పూర్ణాంకం
setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	పూర్ణాంకం ret = 0, saved_errno;

	ఒకవేళ (rgid != sgid) {
		errno = ENOSYS;
		తిరిగి -1;
	}
#ఒకవేళ defined(HAVE_SETREGID) && !defined(BROKEN_SETREGID)
	ఒకవేళ (setregid(rgid, egid) < 0) {
		saved_errno = errno;
		error("setregid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#లేకపోతే
	ఒకవేళ (setegid(egid) < 0) {
		saved_errno = errno;
		error("setegid %lu: %.100s", (u_long)egid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
	ఒకవేళ (setgid(rgid) < 0) {
		saved_errno = errno;
		error("setgid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#అయితే_ముగింపు
	తిరిగి ret;
}
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_SETRESUID) || defined(BROKEN_SETRESUID)
పూర్ణాంకం
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	పూర్ణాంకం ret = 0, saved_errno;

	ఒకవేళ (ruid != suid) {
		errno = ENOSYS;
		తిరిగి -1;
	}
#ఒకవేళ defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
	ఒకవేళ (setreuid(ruid, euid) < 0) {
		saved_errno = errno;
		error("setreuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#లేకపోతే

# ifndef SETEUID_BREAKS_SETUID
	ఒకవేళ (seteuid(euid) < 0) {
		saved_errno = errno;
		error("seteuid %lu: %.100s", (u_long)euid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
# endif
	ఒకవేళ (setuid(ruid) < 0) {
		saved_errno = errno;
		error("setuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#అయితే_ముగింపు
	తిరిగి ret;
}
#అయితే_ముగింపు
