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

#شامل "includes.h"

#اگر !defined(HAVE_GETPEEREID)

#شامل <sys/types.h>
#شامل <sys/socket.h>

#شامل <unistd.h>

#اگر defined(SO_PEERCRED)
صحیح
getpeereid(صحیح s, uid_t *euid, gid_t *gid)
{
	ساختار ucred cred;
	socklen_t len = اندازه(cred);

	اگر (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		بازگشت (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	بازگشت (0);
}
#وگرنهاگر defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

صحیح
getpeereid(صحیح s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = پوچ;

	اگر (getpeerucred(s, &ucred) == -1)
		بازگشت (-1);
	اگر ((*euid = ucred_geteuid(ucred)) == -1)
		بازگشت (-1);
	اگر ((*gid = ucred_getrgid(ucred)) == -1)
		بازگشت (-1);

	ucred_free(ucred);

	بازگشت (0);
}
#وگرنه
صحیح
getpeereid(صحیح s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	بازگشت (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
