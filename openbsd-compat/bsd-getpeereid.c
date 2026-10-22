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

#もし !defined(HAVE_GETPEEREID)

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#もし defined(SO_PEERCRED)
整数
getpeereid(整数 s, uid_t *euid, gid_t *gid)
{
	struct ucred cred;
	socklen_t len = sizeof(cred);

	もし (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		戻る (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	戻る (0);
}
#elif defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

整数
getpeereid(整数 s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = NULL;

	もし (getpeerucred(s, &ucred) == -1)
		戻る (-1);
	もし ((*euid = ucred_geteuid(ucred)) == -1)
		戻る (-1);
	もし ((*gid = ucred_getrgid(ucred)) == -1)
		戻る (-1);

	ucred_free(ucred);

	戻る (0);
}
#否则
整数
getpeereid(整数 s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	戻る (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
