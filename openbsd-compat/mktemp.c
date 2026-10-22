/* THIS FILE HAS BEEN MODIFIED FROM THE ORIGINAL OPENBSD SOURCE */
/* Changes: Removed mktemp */

/*	$OpenBSD: mktemp.c,v 1.30 2010/03/21 23:09:30 schwarze Exp $ */
/*
 * Copyright (c) 1996-1998, 2008 Theo de Raadt
 * Copyright (c) 1997, 2008-2009 Todd C. Miller
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

/* OPENBSD ORIGINAL: lib/libc/stdio/mktemp.c */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ mkstemp
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ mkstemp
#ਜੇ_ਅੰਤ
ਪੂਰਨ mkstemp(ਅੱਖਰ *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
ਪੂਰਨ
_ssh_mkstemp(ਅੱਖਰ *ਸਾਂਚਾ)
{
	ਬਹੁਲਕ_t ਨਕਾਬ;
	ਪੂਰਨ ret;

	ਨਕਾਬ = umask(0177);
	ret = mkstemp(ਸਾਂਚਾ);
	(ਖਾਲੀ)umask(ਨਕਾਬ);
	ਵਾਪਸ ret;
}

#ਜੇ !defined(HAVE_MKDTEMP)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MKTEMP_NAME	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MKTEMP_FILE	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MKTEMP_DIR	2

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਅੰਕ_CHARS	(ਆਕਾਰ(TEMPCHARS) - 1)

ਸਥਿਰ ਪੂਰਨ
mktemp_ਅੰਦਰੂਨੀ(ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ slen, ਪੂਰਨ ਬਹੁਲਕ)
{
	ਅੱਖਰ *ਸ਼ੁਰੂ, *cp, *ep;
	ਅਚਲ ਅੱਖਰ *tempchars = TEMPCHARS;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ r, tries;
	ਬਣਤਰ stat sb;
	ਮਾਪ_t len;
	ਪੂਰਨ fd;

	len = ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ);
	ਜੇ (len == 0 || slen < 0 || (ਮਾਪ_t)slen >= len) {
		errno = EINVAL;
		ਵਾਪਸ(-1);
	}
	ep = ਰਸਤਾ + len - slen;

	tries = 1;
	ਲਈ (ਸ਼ੁਰੂ = ep; ਸ਼ੁਰੂ > ਰਸਤਾ && ਸ਼ੁਰੂ[-1] == 'X'; ਸ਼ੁਰੂ--) {
		ਜੇ (tries < ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ / ਅੰਕ_CHARS)
			tries *= ਅੰਕ_CHARS;
	}
	tries *= 2;

	ਕਰੋ {
		ਲਈ (cp = ਸ਼ੁਰੂ; cp != ep; cp++) {
			r = arc4random_ਇਕਸਾਰ(ਅੰਕ_CHARS);
			*cp = tempchars[r];
		}

		ਚੋਣ (ਬਹੁਲਕ) {
		ਹਾਲਤ MKTEMP_NAME:
			ਜੇ (lstat(ਰਸਤਾ, &sb) != 0)
				ਵਾਪਸ(errno == ENOENT ? 0 : -1);
			ਰੋਕੋ;
		ਹਾਲਤ MKTEMP_FILE:
			fd = open(ਰਸਤਾ, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			ਜੇ (fd != -1 || errno != EEXIST)
				ਵਾਪਸ(fd);
			ਰੋਕੋ;
		ਹਾਲਤ MKTEMP_DIR:
			ਜੇ (mkdir(ਰਸਤਾ, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				ਵਾਪਸ(0);
			ਜੇ (errno != EEXIST)
				ਵਾਪਸ(-1);
			ਰੋਕੋ;
		}
	} ਜਦੋਂ (--tries);

	errno = EEXIST;
	ਵਾਪਸ(-1);
}

#ਜੇ 0
ਅੱਖਰ *_mktemp(ਅੱਖਰ *);

ਅੱਖਰ *
_mktemp(ਅੱਖਰ *ਰਸਤਾ)
{
	ਜੇ (mktemp_ਅੰਦਰੂਨੀ(ਰਸਤਾ, 0, MKTEMP_NAME) == -1)
		ਵਾਪਸ(ਨਿਰਾ);
	ਵਾਪਸ(ਰਸਤਾ);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

ਅੱਖਰ *
mktemp(ਅੱਖਰ *ਰਸਤਾ)
{
	ਵਾਪਸ(_mktemp(ਰਸਤਾ));
}
#ਜੇ_ਅੰਤ

ਪੂਰਨ
mkstemp(ਅੱਖਰ *ਰਸਤਾ)
{
	ਵਾਪਸ(mktemp_ਅੰਦਰੂਨੀ(ਰਸਤਾ, 0, MKTEMP_FILE));
}

ਪੂਰਨ
mkstemps(ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ slen)
{
	ਵਾਪਸ(mktemp_ਅੰਦਰੂਨੀ(ਰਸਤਾ, slen, MKTEMP_FILE));
}

ਅੱਖਰ *
mkdtemp(ਅੱਖਰ *ਰਸਤਾ)
{
	ਪੂਰਨ error;

	error = mktemp_ਅੰਦਰੂਨੀ(ਰਸਤਾ, 0, MKTEMP_DIR);
	ਵਾਪਸ(error ? ਨਿਰਾ : ਰਸਤਾ);
}

#ਜੇ_ਅੰਤ /* !defined(HAVE_MKDTEMP) */
