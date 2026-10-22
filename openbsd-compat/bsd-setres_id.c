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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "log.h"

#यदि !defined(HAVE_SETRESGID) || defined(BROKEN_SETRESGID)
पूर्णाङ्क
setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	पूर्णाङ्क ret = 0, saved_errno;

	यदि (rgid != sgid) {
		त्रुटि_सं = ENOSYS;
		फर्काऊ -1;
	}
#यदि defined(HAVE_SETREGID) && !defined(BROKEN_SETREGID)
	यदि (setregid(rgid, egid) < 0) {
		saved_errno = त्रुटि_सं;
		error("setregid %lu: %.100s", (u_long)rgid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
#अन्यथा
	यदि (setegid(egid) < 0) {
		saved_errno = त्रुटि_सं;
		error("setegid %lu: %.100s", (u_long)egid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
	यदि (setgid(rgid) < 0) {
		saved_errno = त्रुटि_सं;
		error("setgid %lu: %.100s", (u_long)rgid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
#endif
	फर्काऊ ret;
}
#endif

#यदि !defined(HAVE_SETRESUID) || defined(BROKEN_SETRESUID)
पूर्णाङ्क
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	पूर्णाङ्क ret = 0, saved_errno;

	यदि (ruid != suid) {
		त्रुटि_सं = ENOSYS;
		फर्काऊ -1;
	}
#यदि defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
	यदि (setreuid(ruid, euid) < 0) {
		saved_errno = त्रुटि_सं;
		error("setreuid %lu: %.100s", (u_long)ruid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
#अन्यथा

# ifndef SETEUID_BREAKS_SETUID
	यदि (seteuid(euid) < 0) {
		saved_errno = त्रुटि_सं;
		error("seteuid %lu: %.100s", (u_long)euid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
# endif
	यदि (setuid(ruid) < 0) {
		saved_errno = त्रुटि_सं;
		error("setuid %lu: %.100s", (u_long)ruid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
#endif
	फर्काऊ ret;
}
#endif
