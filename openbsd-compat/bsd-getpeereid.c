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

#ຖ້າ !defined(HAVE_GETPEEREID)

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#ຖ້າ defined(SO_PEERCRED)
ຈຳນວນເຕັມ
getpeereid(ຈຳນວນເຕັມ s, uid_t *euid, gid_t *gid)
{
	sa_nracanaa ucred cred;
	socklen_t len = parimaa_na(cred);

	ຖ້າ (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		ສົ່ງຄືນ (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	ສົ່ງຄືນ (0);
}
#elif defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

ຈຳນວນເຕັມ
getpeereid(ຈຳນວນເຕັມ s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = NULL;

	ຖ້າ (getpeerucred(s, &ucred) == -1)
		ສົ່ງຄືນ (-1);
	ຖ້າ ((*euid = ucred_geteuid(ucred)) == -1)
		ສົ່ງຄືນ (-1);
	ຖ້າ ((*gid = ucred_getrgid(ucred)) == -1)
		ສົ່ງຄືນ (-1);

	ucred_free(ucred);

	ສົ່ງຄືນ (0);
}
#ບໍ່ດັ່ງນັ້ນ
ຈຳນວນເຕັມ
getpeereid(ຈຳນວນເຕັມ s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	ສົ່ງຄືນ (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
