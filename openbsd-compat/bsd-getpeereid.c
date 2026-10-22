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

#सचे !defined(HAVE_GETPEEREID)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>

#अन्तर्भाव <unistd.h>

#सचे defined(SO_PEERCRED)
पूर्णाङ्क
getpeereid(पूर्णाङ्क s, uid_t *euid, gid_t *gid)
{
	संरचना ucred cred;
	socklen_t len = परिमाण(cred);

	सचे (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		पटिनिवत्त (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	पटिनिवत्त (0);
}
#नोचेद्यदि defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

पूर्णाङ्क
getpeereid(पूर्णाङ्क s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = रिक्त;

	सचे (getpeerucred(s, &ucred) == -1)
		पटिनिवत्त (-1);
	सचे ((*euid = ucred_geteuid(ucred)) == -1)
		पटिनिवत्त (-1);
	सचे ((*gid = ucred_getrgid(ucred)) == -1)
		पटिनिवत्त (-1);

	ucred_free(ucred);

	पटिनिवत्त (0);
}
#अञ्ञथा
पूर्णाङ्क
getpeereid(पूर्णाङ्क s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	पटिनिवत्त (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
