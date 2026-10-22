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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdarg.h>
#شامل <unistd.h>
#شامل <string.h>

#شامل "log.h"

#اگر !defined(HAVE_SETRESGID) || defined(BROKEN_SETRESGID)
صحیح
setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	صحیح ret = 0, saved_errno;

	اگر (rgid != sgid) {
		errno = ENOSYS;
		بازگشت -1;
	}
#اگر defined(HAVE_SETREGID) && !defined(BROKEN_SETREGID)
	اگر (setregid(rgid, egid) < 0) {
		saved_errno = errno;
		error("setregid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#وگرنه
	اگر (setegid(egid) < 0) {
		saved_errno = errno;
		error("setegid %lu: %.100s", (u_long)egid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
	اگر (setgid(rgid) < 0) {
		saved_errno = errno;
		error("setgid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#endif
	بازگشت ret;
}
#endif

#اگر !defined(HAVE_SETRESUID) || defined(BROKEN_SETRESUID)
صحیح
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	صحیح ret = 0, saved_errno;

	اگر (ruid != suid) {
		errno = ENOSYS;
		بازگشت -1;
	}
#اگر defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
	اگر (setreuid(ruid, euid) < 0) {
		saved_errno = errno;
		error("setreuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#وگرنه

# ifndef SETEUID_BREAKS_SETUID
	اگر (seteuid(euid) < 0) {
		saved_errno = errno;
		error("seteuid %lu: %.100s", (u_long)euid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
# endif
	اگر (setuid(ruid) < 0) {
		saved_errno = errno;
		error("setuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#endif
	بازگشت ret;
}
#endif
