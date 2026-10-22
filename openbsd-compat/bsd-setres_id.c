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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdarg.h>
#समावेश <unistd.h>
#समावेश <string.h>

#समावेश "log.h"

#अगर !defined(HAVE_SETRESGID) || defined(BROKEN_SETRESGID)
पूर्णांक
setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	पूर्णांक ret = 0, saved_errno;

	अगर (rgid != sgid) {
		त्रुटि_सं = ENOSYS;
		वापस -1;
	}
#अगर defined(HAVE_SETREGID) && !defined(BROKEN_SETREGID)
	अगर (setregid(rgid, egid) < 0) {
		saved_errno = त्रुटि_सं;
		error("setregid %lu: %.100s", (u_long)rgid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
#अन्यथा
	अगर (setegid(egid) < 0) {
		saved_errno = त्रुटि_सं;
		error("setegid %lu: %.100s", (u_long)egid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
	अगर (setgid(rgid) < 0) {
		saved_errno = त्रुटि_सं;
		error("setgid %lu: %.100s", (u_long)rgid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
#पूर्ण_अगर
	वापस ret;
}
#पूर्ण_अगर

#अगर !defined(HAVE_SETRESUID) || defined(BROKEN_SETRESUID)
पूर्णांक
setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	पूर्णांक ret = 0, saved_errno;

	अगर (ruid != suid) {
		त्रुटि_सं = ENOSYS;
		वापस -1;
	}
#अगर defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
	अगर (setreuid(ruid, euid) < 0) {
		saved_errno = त्रुटि_सं;
		error("setreuid %lu: %.100s", (u_long)ruid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
#अन्यथा

# ifndef SETEUID_BREAKS_SETUID
	अगर (seteuid(euid) < 0) {
		saved_errno = त्रुटि_सं;
		error("seteuid %lu: %.100s", (u_long)euid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
# endif
	अगर (setuid(ruid) < 0) {
		saved_errno = त्रुटि_सं;
		error("setuid %lu: %.100s", (u_long)ruid, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = saved_errno;
		ret = -1;
	}
#पूर्ण_अगर
	वापस ret;
}
#पूर्ण_अगर
