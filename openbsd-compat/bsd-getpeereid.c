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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ !defined(HAVE_GETPEEREID)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ defined(SO_PEERCRED)
ਪੂਰਨ
getpeereid(ਪੂਰਨ s, uid_t *euid, gid_t *gid)
{
	ਬਣਤਰ ucred cred;
	socklen_t len = ਆਕਾਰ(cred);

	ਜੇ (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		ਵਾਪਸ (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	ਵਾਪਸ (0);
}
#ਜਾਂਜੇ defined(HAVE_GETPEERUCRED)

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_UCRED_H
# include <ucred.h>
#ਜੇ_ਅੰਤ

ਪੂਰਨ
getpeereid(ਪੂਰਨ s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = ਨਿਰਾ;

	ਜੇ (getpeerucred(s, &ucred) == -1)
		ਵਾਪਸ (-1);
	ਜੇ ((*euid = ucred_geteuid(ucred)) == -1)
		ਵਾਪਸ (-1);
	ਜੇ ((*gid = ucred_getrgid(ucred)) == -1)
		ਵਾਪਸ (-1);

	ucred_free(ucred);

	ਵਾਪਸ (0);
}
#ਨਹੀਂਤਾਂ
ਪੂਰਨ
getpeereid(ਪੂਰਨ s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	ਵਾਪਸ (0);
}
#ਜੇ_ਅੰਤ /* defined(SO_PEERCRED) */

#ਜੇ_ਅੰਤ /* !defined(HAVE_GETPEEREID) */
