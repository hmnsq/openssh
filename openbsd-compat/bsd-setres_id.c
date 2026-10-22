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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "log.h"

#எனில் !defined(HAVE_SETRESGID) || defined(BROKEN_SETRESGID)
முழு
setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	முழு ret = 0, saved_errno;

	எனில் (rgid != sgid) {
		errno = ENOSYS;
		திரும்பு -1;
	}
#எனில் defined(HAVE_SETREGID) && !defined(BROKEN_SETREGID)
	எனில் (setregid(rgid, egid) < 0) {
		saved_errno = errno;
		error("setregid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#இல்லையெனில்
	எனில் (setegid(egid) < 0) {
		saved_errno = errno;
		error("setegid %lu: %.100s", (u_long)egid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
	எனில் (setgid(rgid) < 0) {
		saved_errno = errno;
		error("setgid %lu: %.100s", (u_long)rgid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#endif
	திரும்பு ret;
}
#endif

#எனில் !defined(HAVE_SETRESUID) || defined(BROKEN_SETRESUID)
முழு
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	முழு ret = 0, saved_errno;

	எனில் (ruid != suid) {
		errno = ENOSYS;
		திரும்பு -1;
	}
#எனில் defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
	எனில் (setreuid(ruid, euid) < 0) {
		saved_errno = errno;
		error("setreuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#இல்லையெனில்

# ifndef SETEUID_BREAKS_SETUID
	எனில் (seteuid(euid) < 0) {
		saved_errno = errno;
		error("seteuid %lu: %.100s", (u_long)euid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
# endif
	எனில் (setuid(ruid) < 0) {
		saved_errno = errno;
		error("setuid %lu: %.100s", (u_long)ruid, strerror(errno));
		errno = saved_errno;
		ret = -1;
	}
#endif
	திரும்பு ret;
}
#endif
