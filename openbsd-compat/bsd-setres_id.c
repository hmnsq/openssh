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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਜੇ !defined(HAVE_SETRESGID) || defined(BROKEN_SETRESGID)
ਪੂਰਨ
setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	ਪੂਰਨ ret = 0, saved_errno;

	ਜੇ (rgid != sgid) {
		errno = ENOSYS;
		ਵਾਪਸ -1;
	}
#ਜੇ defined(HAVE_SETREGID) && !defined(BROKEN_SETREGID)
	ਜੇ (setregid(rgid, egid) < 0) {
		saved_errno = errno;
		error("setregid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#ਨਹੀਂਤਾਂ
	ਜੇ (setegid(egid) < 0) {
		saved_errno = errno;
		error("setegid %lu: %.100s", (u_long)egid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
	ਜੇ (setgid(rgid) < 0) {
		saved_errno = errno;
		error("setgid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#ਜੇ_ਅੰਤ
	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_SETRESUID) || defined(BROKEN_SETRESUID)
ਪੂਰਨ
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	ਪੂਰਨ ret = 0, saved_errno;

	ਜੇ (ruid != suid) {
		errno = ENOSYS;
		ਵਾਪਸ -1;
	}
#ਜੇ defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
	ਜੇ (setreuid(ruid, euid) < 0) {
		saved_errno = errno;
		error("setreuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#ਨਹੀਂਤਾਂ

# ifndef SETEUID_BREAKS_SETUID
	ਜੇ (seteuid(euid) < 0) {
		saved_errno = errno;
		error("seteuid %lu: %.100s", (u_long)euid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
# endif
	ਜੇ (setuid(ruid) < 0) {
		saved_errno = errno;
		error("setuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#ਜੇ_ਅੰਤ
	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ
