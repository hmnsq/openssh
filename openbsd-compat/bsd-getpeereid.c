/*
 * Copyright (c) 2002,2004 Damien Miller <djm@mindrot.org>
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

#ضمن "includes.h"

#إذا !defined(HAVE_GETPEEREID)

#ضمن <sys/types.h>
#ضمن <sys/socket.h>

#ضمن <unistd.h>

#إذا defined(SO_PEERCRED)
صحيح
getpeereid(صحيح s, uid_t *euid, gid_t *gid)
{
	بنية ucred cred;
	socklen_t len = حجم(cred);

	إذا (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		أرجع (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	أرجع (0);
}
#وإلاإذا defined(HAVE_GETPEERUCRED)

#جيڪڏهن_وصف_ٿيل HAVE_UCRED_H
# include <ucred.h>
#جيڪڏهن_پورو

صحيح
getpeereid(صحيح s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = عدم;

	إذا (getpeerucred(s, &ucred) == -1)
		أرجع (-1);
	إذا ((*euid = ucred_geteuid(ucred)) == -1)
		أرجع (-1);
	إذا ((*gid = ucred_getrgid(ucred)) == -1)
		أرجع (-1);

	ucred_free(ucred);

	أرجع (0);
}
#وإلا
صحيح
getpeereid(صحيح s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	أرجع (0);
}
#جيڪڏهن_پورو /* defined(SO_PEERCRED) */

#جيڪڏهن_پورو /* !defined(HAVE_GETPEEREID) */
