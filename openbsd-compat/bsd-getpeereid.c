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

#ако !defined(HAVE_GETPEEREID)

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#ако defined(SO_PEERCRED)
цяло
getpeereid(цяло s, uid_t *euid, gid_t *gid)
{
	struct ucred cred;
	socklen_t len = sizeof(cred);

	ако (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		върни (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	върни (0);
}
#elif defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

цяло
getpeereid(цяло s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = NULL;

	ако (getpeerucred(s, &ucred) == -1)
		върни (-1);
	ако ((*euid = ucred_geteuid(ucred)) == -1)
		върни (-1);
	ако ((*gid = ucred_getrgid(ucred)) == -1)
		върни (-1);

	ucred_free(ucred);

	върни (0);
}
#иначе
цяло
getpeereid(цяло s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	върни (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
