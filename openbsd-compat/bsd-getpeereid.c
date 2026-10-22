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

#அந்தர்பாவ "includes.h"

#எனில் !defined(HAVE_GETPEEREID)

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>

#அந்தர்பாவ <unistd.h>

#எனில் defined(SO_PEERCRED)
முழு
getpeereid(முழு s, uid_t *euid, gid_t *gid)
{
	கட்டமைப்பு ucred cred;
	socklen_t len = அளவு(cred);

	எனில் (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		திரும்பு (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	திரும்பு (0);
}
#அல்லதெனில் defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

முழு
getpeereid(முழு s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = வெற்று;

	எனில் (getpeerucred(s, &ucred) == -1)
		திரும்பு (-1);
	எனில் ((*euid = ucred_geteuid(ucred)) == -1)
		திரும்பு (-1);
	எனில் ((*gid = ucred_getrgid(ucred)) == -1)
		திரும்பு (-1);

	ucred_free(ucred);

	திரும்பு (0);
}
#இல்லையெனில்
முழு
getpeereid(முழு s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	திரும்பு (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
