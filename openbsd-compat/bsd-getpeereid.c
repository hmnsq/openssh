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

#अन्तर्भाव "includes.h"

#जर !defined(HAVE_GETPEEREID)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <unistd.h>

#जर defined(SO_PEERCRED)
पूर्णांक
getpeereid(पूर्णांक s, uid_t *euid, gid_t *gid)
{
	संरचना ucred cred;
	socklen_t len = आकार(cred);

	जर (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		परत (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	परत (0);
}
#किंवाजर defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

पूर्णांक
getpeereid(पूर्णांक s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = रिक्त;

	जर (getpeerucred(s, &ucred) == -1)
		परत (-1);
	जर ((*euid = ucred_geteuid(ucred)) == -1)
		परत (-1);
	जर ((*gid = ucred_getrgid(ucred)) == -1)
		परत (-1);

	ucred_free(ucred);

	परत (0);
}
#अन्यथा
पूर्णांक
getpeereid(पूर्णांक s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	परत (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
