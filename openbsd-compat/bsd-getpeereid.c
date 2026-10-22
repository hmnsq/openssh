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
	ساخت ucred cred;
	socklen_t len = حجم(cred);

	اگر (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		واپس (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	واپس (0);
}
#وگرنہ_اگر defined(HAVE_GETPEERUCRED)

#اگر_تعریف_شدہ HAVE_UCRED_H
# include <ucred.h>
#اگر_ختم

صحیح
getpeereid(صحیح s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = تہی;

	اگر (getpeerucred(s, &ucred) == -1)
		واپس (-1);
	اگر ((*euid = ucred_geteuid(ucred)) == -1)
		واپس (-1);
	اگر ((*gid = ucred_getrgid(ucred)) == -1)
		واپس (-1);

	ucred_free(ucred);

	واپس (0);
}
#ورنہ
صحیح
getpeereid(صحیح s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	واپس (0);
}
#اگر_ختم /* defined(SO_PEERCRED) */

#اگر_ختم /* !defined(HAVE_GETPEEREID) */
