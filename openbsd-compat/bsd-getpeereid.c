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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಆದರೆ !defined(HAVE_GETPEEREID)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಆದರೆ defined(SO_PEERCRED)
ಪೂರ್ಣಾಂಕ
getpeereid(ಪೂರ್ಣಾಂಕ s, uid_t *euid, gid_t *gid)
{
	ರಚನೆ ucred cred;
	socklen_t len = ಗಾತ್ರ(cred);

	ಆದರೆ (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		ಹಿಂತಿರುಗಿ (-1);
	*euid = cred.uid;
	*gid = cred.gid;

	ಹಿಂತಿರುಗಿ (0);
}
#ಅಥವಾಆದರೆ defined(HAVE_GETPEERUCRED)

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_UCRED_H
# include <ucred.h>
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
getpeereid(ಪೂರ್ಣಾಂಕ s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = ಖಾಲಿ;

	ಆದರೆ (getpeerucred(s, &ucred) == -1)
		ಹಿಂತಿರುಗಿ (-1);
	ಆದರೆ ((*euid = ucred_geteuid(ucred)) == -1)
		ಹಿಂತಿರುಗಿ (-1);
	ಆದರೆ ((*gid = ucred_getrgid(ucred)) == -1)
		ಹಿಂತಿರುಗಿ (-1);

	ucred_free(ucred);

	ಹಿಂತಿರುಗಿ (0);
}
#ಇಲ್ಲದಿದ್ದರೆ
ಪೂರ್ಣಾಂಕ
getpeereid(ಪೂರ್ಣಾಂಕ s, uid_t *euid, gid_t *gid)
{
	*euid = geteuid();
	*gid = getgid();

	ಹಿಂತಿರುಗಿ (0);
}
#ಆದರೆ_ಅಂತ್ಯ /* defined(SO_PEERCRED) */

#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_GETPEEREID) */
