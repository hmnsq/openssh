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

#समावेश "includes.h"

#अगर !defined(HAVE_GETPEEREID)

#समावेश <sys/types.h>
#समावेश <sys/socket.h>

#समावेश <unistd.h>

#अगर defined(SO_PEERCRED)
पूर्णांक
getpeereid(पूर्णांक s, uid_t *euid, gid_t *gid)
{
	काष्ठा ucred cred;
	socklen_t len = माप(cred);

	अगर (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		वापस (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	वापस (0);
}
#या_अगर defined(HAVE_GETPEERUCRED)

#अगर_घोषित HAVE_UCRED_H
# include <ucred.h>
#पूर्ण_अगर

पूर्णांक
getpeereid(पूर्णांक s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = शून्य;

	अगर (getpeerucred(s, &ucred) == -1)
		वापस (-1);
	अगर ((*euid = ucred_geteuid(ucred)) == -1)
		वापस (-1);
	अगर ((*gid = ucred_getrgid(ucred)) == -1)
		वापस (-1);

	ucred_free(ucred);

	वापस (0);
}
#अन्यथा
पूर्णांक
getpeereid(पूर्णांक s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	वापस (0);
}
#पूर्ण_अगर /* defined(SO_PEERCRED) */

#पूर्ण_अगर /* !defined(HAVE_GETPEEREID) */
