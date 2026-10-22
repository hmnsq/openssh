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

#གལ་ཏེ !defined(HAVE_GETPEEREID)

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#གལ་ཏེ defined(SO_PEERCRED)
ཧྲིལ
getpeereid(ཧྲིལ s, uid_t *euid, gid_t *gid)
{
	sa_nracanaa ucred cred;
	socklen_t len = parimaa_na(cred);

	གལ་ཏེ (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		ཕྱིར (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	ཕྱིར (0);
}
#elif defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

ཧྲིལ
getpeereid(ཧྲིལ s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = NULL;

	གལ་ཏེ (getpeerucred(s, &ucred) == -1)
		ཕྱིར (-1);
	གལ་ཏེ ((*euid = ucred_geteuid(ucred)) == -1)
		ཕྱིར (-1);
	གལ་ཏེ ((*gid = ucred_getrgid(ucred)) == -1)
		ཕྱིར (-1);

	ucred_free(ucred);

	ཕྱིར (0);
}
#དེ་མིན
ཧྲིལ
getpeereid(ཧྲིལ s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	ཕྱིར (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
