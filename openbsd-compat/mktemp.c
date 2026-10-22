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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
ಪೂರ್ಣಾಙ್ಕ mkstemp(ವರ್ಣ *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
ಪೂರ್ಣಾಙ್ಕ
_ssh_mkstemp(ವರ್ಣ *template)
{
	mode_t mask;
	ಪೂರ್ಣಾಙ್ಕ ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(ಶೂನ್ಯ)umask(mask);
	ಪ್ರತ್ಯಾಗಮ ret;
}

#ಯದಿ !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define ಅಂಕೆ_CHARS	(ಪರಿಮಾಣ(TEMPCHARS) - 1)

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mktemp_internal(ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ slen, ಪೂರ್ಣಾಙ್ಕ mode)
{
	ವರ್ಣ *start, *cp, *ep;
	ಧ್ರುವ ವರ್ಣ *tempchars = TEMPCHARS;
	unsigned ಪೂರ್ಣಾಙ್ಕ r, tries;
	ಸಂರಚನಾ stat sb;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ fd;

	len = strlen(path);
	ಯದಿ (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ(-1);
	}
	ep = path + len - slen;

	tries = 1;
	ಪ್ರತಿ (start = ep; start > path && start[-1] == 'X'; start--) {
		ಯದಿ (tries < INT_MAX / ಅಂಕೆ_CHARS)
			tries *= ಅಂಕೆ_CHARS;
	}
	tries *= 2;

	ಕುರು {
		ಪ್ರತಿ (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(ಅಂಕೆ_CHARS);
			*cp = tempchars[r];
		}

		ವಿಕಲ್ಪ (mode) {
		ಪಕ್ಷ MKTEMP_NAME:
			ಯದಿ (lstat(path, &sb) != 0)
				ಪ್ರತ್ಯಾಗಮ(errno == ENOENT ? 0 : -1);
			ಭಙ್ಗ;
		ಪಕ್ಷ MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			ಯದಿ (fd != -1 || errno != EEXIST)
				ಪ್ರತ್ಯಾಗಮ(fd);
			ಭಙ್ಗ;
		ಪಕ್ಷ MKTEMP_DIR:
			ಯದಿ (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				ಪ್ರತ್ಯಾಗಮ(0);
			ಯದಿ (errno != EEXIST)
				ಪ್ರತ್ಯಾಗಮ(-1);
			ಭಙ್ಗ;
		}
	} ಯಾವತ್ (--tries);

	errno = EEXIST;
	ಪ್ರತ್ಯಾಗಮ(-1);
}

#ಯದಿ 0
ವರ್ಣ *_mktemp(ವರ್ಣ *);

ವರ್ಣ *
_mktemp(ವರ್ಣ *path)
{
	ಯದಿ (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		ಪ್ರತ್ಯಾಗಮ(ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

ವರ್ಣ *
mktemp(ವರ್ಣ *path)
{
	ಪ್ರತ್ಯಾಗಮ(_mktemp(path));
}
#endif

ಪೂರ್ಣಾಙ್ಕ
mkstemp(ವರ್ಣ *path)
{
	ಪ್ರತ್ಯಾಗಮ(mktemp_internal(path, 0, MKTEMP_FILE));
}

ಪೂರ್ಣಾಙ್ಕ
mkstemps(ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ slen)
{
	ಪ್ರತ್ಯಾಗಮ(mktemp_internal(path, slen, MKTEMP_FILE));
}

ವರ್ಣ *
mkdtemp(ವರ್ಣ *path)
{
	ಪೂರ್ಣಾಙ್ಕ error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	ಪ್ರತ್ಯಾಗಮ(error ? ರಿಕ್ತ : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
