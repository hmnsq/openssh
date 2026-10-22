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

#include "includes.h"

#ถ้า !defined(HAVE_GETPEEREID)

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#ถ้า defined(SO_PEERCRED)
จำนวนเต็ม
getpeereid(จำนวนเต็ม s, uid_t *euid, gid_t *gid)
{
	sa_nracanaa ucred cred;
	socklen_t len = parimaa_na(cred);

	ถ้า (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		คืน (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	คืน (0);
}
#elif defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

จำนวนเต็ม
getpeereid(จำนวนเต็ม s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = NULL;

	ถ้า (getpeerucred(s, &ucred) == -1)
		คืน (-1);
	ถ้า ((*euid = ucred_geteuid(ucred)) == -1)
		คืน (-1);
	ถ้า ((*gid = ucred_getrgid(ucred)) == -1)
		คืน (-1);

	ucred_free(ucred);

	คืน (0);
}
#มิฉะนั้น
จำนวนเต็ม
getpeereid(จำนวนเต็ม s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	คืน (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
