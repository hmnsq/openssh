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

#include "includes.h"

#include <sys/types.h>

#include <stdarg.h>
#include <unistd.h>
#include <string.h>

#include "log.h"

#གལ་ཏེ !defined(HAVE_SETRESGID) || defined(BROKEN_SETRESGID)
ཧྲིལ
setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	ཧྲིལ ret = 0, saved_errno;

	གལ་ཏེ (rgid != sgid) {
		errno = ENOSYS;
		ཕྱིར -1;
	}
#གལ་ཏེ defined(HAVE_SETREGID) && !defined(BROKEN_SETREGID)
	གལ་ཏེ (setregid(rgid, egid) < 0) {
		saved_errno = errno;
		error("setregid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#དེ་མིན
	གལ་ཏེ (setegid(egid) < 0) {
		saved_errno = errno;
		error("setegid %lu: %.100s", (u_long)egid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
	གལ་ཏེ (setgid(rgid) < 0) {
		saved_errno = errno;
		error("setgid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#endif
	ཕྱིར ret;
}
#endif

#གལ་ཏེ !defined(HAVE_SETRESUID) || defined(BROKEN_SETRESUID)
ཧྲིལ
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	ཧྲིལ ret = 0, saved_errno;

	གལ་ཏེ (ruid != suid) {
		errno = ENOSYS;
		ཕྱིར -1;
	}
#གལ་ཏེ defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
	གལ་ཏེ (setreuid(ruid, euid) < 0) {
		saved_errno = errno;
		error("setreuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#དེ་མིན

# ifndef SETEUID_BREAKS_SETUID
	གལ་ཏེ (seteuid(euid) < 0) {
		saved_errno = errno;
		error("seteuid %lu: %.100s", (u_long)euid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
# endif
	གལ་ཏེ (setuid(ruid) < 0) {
		saved_errno = errno;
		error("setuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#endif
	ཕྱིར ret;
}
#endif
