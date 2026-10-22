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

#ប្រសិនបើ !defined(HAVE_GETPEEREID)

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#ប្រសិនបើ defined(SO_PEERCRED)
ចំនួនគត់
getpeereid(ចំនួនគត់ s, uid_t *euid, gid_t *gid)
{
	sa_nracanaa ucred cred;
	socklen_t len = parimaa_na(cred);

	ប្រសិនបើ (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		ត្រឡប់ (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	ត្រឡប់ (0);
}
#elif defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

ចំនួនគត់
getpeereid(ចំនួនគត់ s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = NULL;

	ប្រសិនបើ (getpeerucred(s, &ucred) == -1)
		ត្រឡប់ (-1);
	ប្រសិនបើ ((*euid = ucred_geteuid(ucred)) == -1)
		ត្រឡប់ (-1);
	ប្រសិនបើ ((*gid = ucred_getrgid(ucred)) == -1)
		ត្រឡប់ (-1);

	ucred_free(ucred);

	ត្រឡប់ (0);
}
#បើមិនដូច្នេះ
ចំនួនគត់
getpeereid(ចំនួនគត់ s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	ត្រឡប់ (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
