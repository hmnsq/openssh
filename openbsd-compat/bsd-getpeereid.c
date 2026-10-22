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

#അന്തര്ഭാവ "includes.h"

#എങ്കിൽ !defined(HAVE_GETPEEREID)

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>

#അന്തര്ഭാവ <unistd.h>

#എങ്കിൽ defined(SO_PEERCRED)
പൂർണ്ണസംഖ്യ
getpeereid(പൂർണ്ണസംഖ്യ s, uid_t *euid, gid_t *gid)
{
	ഘടന ucred cred;
	socklen_t len = വലുപ്പം(cred);

	എങ്കിൽ (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		തിരികെ (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	തിരികെ (0);
}
#അല്ലെങ്കിലെങ്കിൽ defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

പൂർണ്ണസംഖ്യ
getpeereid(പൂർണ്ണസംഖ്യ s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = ശൂന്യ;

	എങ്കിൽ (getpeerucred(s, &ucred) == -1)
		തിരികെ (-1);
	എങ്കിൽ ((*euid = ucred_geteuid(ucred)) == -1)
		തിരികെ (-1);
	എങ്കിൽ ((*gid = ucred_getrgid(ucred)) == -1)
		തിരികെ (-1);

	ucred_free(ucred);

	തിരികെ (0);
}
#അല്ലെങ്കിൽ
പൂർണ്ണസംഖ്യ
getpeereid(പൂർണ്ണസംഖ്യ s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	തിരികെ (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
