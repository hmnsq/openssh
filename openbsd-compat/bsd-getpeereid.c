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

#অন্তর্ভাব "includes.h"

#যদি !defined(HAVE_GETPEEREID)

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>

#অন্তর্ভাব <unistd.h>

#যদি defined(SO_PEERCRED)
পূর্ণসংখ্যা
getpeereid(পূর্ণসংখ্যা s, uid_t *euid, gid_t *gid)
{
	কাঠামো ucred cred;
	socklen_t len = আকার(cred);

	যদি (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		ফেরত (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	ফেরত (0);
}
#নতুবা_যদি defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

পূর্ণসংখ্যা
getpeereid(পূর্ণসংখ্যা s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = ফাঁকা;

	যদি (getpeerucred(s, &ucred) == -1)
		ফেরত (-1);
	যদি ((*euid = ucred_geteuid(ucred)) == -1)
		ফেরত (-1);
	যদি ((*gid = ucred_getrgid(ucred)) == -1)
		ফেরত (-1);

	ucred_free(ucred);

	ফেরত (0);
}
#অন্যথা
পূর্ণসংখ্যা
getpeereid(পূর্ণসংখ্যা s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	ফেরত (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
