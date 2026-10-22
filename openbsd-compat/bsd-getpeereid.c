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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି !defined(HAVE_GETPEEREID)

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଯଦି defined(SO_PEERCRED)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getpeereid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s, uid_t *euid, gid_t *gid)
{
	ସଂରଚନା ucred cred;
	socklen_t len = ଆକାର(cred);

	ଯଦି (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		ଫେରନ୍ତୁ (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	ଫେରନ୍ତୁ (0);
}
#ନଚେତଯଦି defined(HAVE_GETPEERUCRED)

#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getpeereid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = ଖାଲି;

	ଯଦି (getpeerucred(s, &ucred) == -1)
		ଫେରନ୍ତୁ (-1);
	ଯଦି ((*euid = ucred_geteuid(ucred)) == -1)
		ଫେରନ୍ତୁ (-1);
	ଯଦି ((*gid = ucred_getrgid(ucred)) == -1)
		ଫେରନ୍ତୁ (-1);

	ucred_free(ucred);

	ଫେରନ୍ତୁ (0);
}
#ଅନ୍ୟଥା
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getpeereid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	ଫେରନ୍ତୁ (0);
}
#endif /* defined(SO_PEERCRED) */

#endif /* !defined(HAVE_GETPEEREID) */
