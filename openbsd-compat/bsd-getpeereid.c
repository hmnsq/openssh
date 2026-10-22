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

#అన్తర్భావ "includes.h"

#ఒకవేళ !defined(HAVE_GETPEEREID)

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>

#అన్తర్భావ <unistd.h>

#ఒకవేళ defined(SO_PEERCRED)
పూర్ణాంకం
getpeereid(పూర్ణాంకం s, uid_t *euid, gid_t *gid)
{
	నిర్మాణం ucred cred;
	socklen_t len = పరిమాణం(cred);

	ఒకవేళ (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		తిరిగి (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	తిరిగి (0);
}
#లేదావేళ defined(HAVE_GETPEERUCRED)

#నిర్వచితమైతే HAVE_UCRED_H
# include <ucred.h>
#అయితే_ముగింపు

పూర్ణాంకం
getpeereid(పూర్ణాంకం s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = ఖాళీ;

	ఒకవేళ (getpeerucred(s, &ucred) == -1)
		తిరిగి (-1);
	ఒకవేళ ((*euid = ucred_geteuid(ucred)) == -1)
		తిరిగి (-1);
	ఒకవేళ ((*gid = ucred_getrgid(ucred)) == -1)
		తిరిగి (-1);

	ucred_free(ucred);

	తిరిగి (0);
}
#లేకపోతే
పూర్ణాంకం
getpeereid(పూర్ణాంకం s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	తిరిగి (0);
}
#అయితే_ముగింపు /* defined(SO_PEERCRED) */

#అయితే_ముగింపు /* !defined(HAVE_GETPEEREID) */
