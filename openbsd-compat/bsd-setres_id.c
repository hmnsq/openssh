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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "log.h"

#ଯଦି !defined(HAVE_SETRESGID) || defined(BROKEN_SETRESGID)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = 0, saved_errno;

	ଯଦି (rgid != sgid) {
		errno = ENOSYS;
		ଫେରନ୍ତୁ -1;
	}
#ଯଦି defined(HAVE_SETREGID) && !defined(BROKEN_SETREGID)
	ଯଦି (setregid(rgid, egid) < 0) {
		saved_errno = errno;
		error("setregid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#ଅନ୍ୟଥା
	ଯଦି (setegid(egid) < 0) {
		saved_errno = errno;
		error("setegid %lu: %.100s", (u_long)egid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
	ଯଦି (setgid(rgid) < 0) {
		saved_errno = errno;
		error("setgid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#endif
	ଫେରନ୍ତୁ ret;
}
#endif

#ଯଦି !defined(HAVE_SETRESUID) || defined(BROKEN_SETRESUID)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = 0, saved_errno;

	ଯଦି (ruid != suid) {
		errno = ENOSYS;
		ଫେରନ୍ତୁ -1;
	}
#ଯଦି defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
	ଯଦି (setreuid(ruid, euid) < 0) {
		saved_errno = errno;
		error("setreuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#ଅନ୍ୟଥା

# ifndef SETEUID_BREAKS_SETUID
	ଯଦି (seteuid(euid) < 0) {
		saved_errno = errno;
		error("seteuid %lu: %.100s", (u_long)euid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
# endif
	ଯଦି (setuid(ruid) < 0) {
		saved_errno = errno;
		error("setuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#endif
	ଫେରନ୍ତୁ ret;
}
#endif
