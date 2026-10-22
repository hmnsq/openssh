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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ mkstemp
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು mkstemp
#ಆದರೆ_ಅಂತ್ಯ
ಪೂರ್ಣಾಂಕ mkstemp(ಅಕ್ಷರ *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
ಪೂರ್ಣಾಂಕ
_ssh_mkstemp(ಅಕ್ಷರ *ಮಾದರಿ)
{
	ಬಹುಲಕ_t ಮುಖವಾಡ;
	ಪೂರ್ಣಾಂಕ ret;

	ಮುಖವಾಡ = umask(0177);
	ret = mkstemp(ಮಾದರಿ);
	(ಶೂನ್ಯ)umask(ಮುಖವಾಡ);
	ಹಿಂತಿರುಗಿ ret;
}

#ಆದರೆ !defined(HAVE_MKDTEMP)

#ವ್ಯಾಖ್ಯಾನಿಸು MKTEMP_NAME	0
#ವ್ಯಾಖ್ಯಾನಿಸು MKTEMP_FILE	1
#ವ್ಯಾಖ್ಯಾನಿಸು MKTEMP_DIR	2

#ವ್ಯಾಖ್ಯಾನಿಸು TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#ವ್ಯಾಖ್ಯಾನಿಸು ಅಂಕೆ_CHARS	(ಗಾತ್ರ(TEMPCHARS) - 1)

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mktemp_ಆಂತರಿಕ(ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ slen, ಪೂರ್ಣಾಂಕ ಬಹುಲಕ)
{
	ಅಕ್ಷರ *ಆರಂಭ, *cp, *ep;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tempchars = TEMPCHARS;
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ r, tries;
	ರಚನೆ stat sb;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ fd;

	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ);
	ಆದರೆ (len == 0 || slen < 0 || (ಗಾತ್ರ_t)slen >= len) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ(-1);
	}
	ep = ಮಾರ್ಗ + len - slen;

	tries = 1;
	ಗಾಗಿ (ಆರಂಭ = ep; ಆರಂಭ > ಮಾರ್ಗ && ಆರಂಭ[-1] == 'X'; ಆರಂಭ--) {
		ಆದರೆ (tries < ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ / ಅಂಕೆ_CHARS)
			tries *= ಅಂಕೆ_CHARS;
	}
	tries *= 2;

	ಮಾಡು {
		ಗಾಗಿ (cp = ಆರಂಭ; cp != ep; cp++) {
			r = arc4random_ಏಕರೂಪ(ಅಂಕೆ_CHARS);
			*cp = tempchars[r];
		}

		ಆಯ್ಕೆ (ಬಹುಲಕ) {
		ಸ್ಥಿತಿ MKTEMP_NAME:
			ಆದರೆ (lstat(ಮಾರ್ಗ, &sb) != 0)
				ಹಿಂತಿರುಗಿ(errno == ENOENT ? 0 : -1);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ MKTEMP_FILE:
			fd = open(ಮಾರ್ಗ, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			ಆದರೆ (fd != -1 || errno != EEXIST)
				ಹಿಂತಿರುಗಿ(fd);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ MKTEMP_DIR:
			ಆದರೆ (mkdir(ಮಾರ್ಗ, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				ಹಿಂತಿರುಗಿ(0);
			ಆದರೆ (errno != EEXIST)
				ಹಿಂತಿರುಗಿ(-1);
			ನಿಲ್ಲಿಸು;
		}
	} ಆಗ (--tries);

	errno = EEXIST;
	ಹಿಂತಿರುಗಿ(-1);
}

#ಆದರೆ 0
ಅಕ್ಷರ *_mktemp(ಅಕ್ಷರ *);

ಅಕ್ಷರ *
_mktemp(ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಆದರೆ (mktemp_ಆಂತರಿಕ(ಮಾರ್ಗ, 0, MKTEMP_NAME) == -1)
		ಹಿಂತಿರುಗಿ(ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ(ಮಾರ್ಗ);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

ಅಕ್ಷರ *
mktemp(ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಹಿಂತಿರುಗಿ(_mktemp(ಮಾರ್ಗ));
}
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
mkstemp(ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಹಿಂತಿರುಗಿ(mktemp_ಆಂತರಿಕ(ಮಾರ್ಗ, 0, MKTEMP_FILE));
}

ಪೂರ್ಣಾಂಕ
mkstemps(ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ slen)
{
	ಹಿಂತಿರುಗಿ(mktemp_ಆಂತರಿಕ(ಮಾರ್ಗ, slen, MKTEMP_FILE));
}

ಅಕ್ಷರ *
mkdtemp(ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಪೂರ್ಣಾಂಕ error;

	error = mktemp_ಆಂತರಿಕ(ಮಾರ್ಗ, 0, MKTEMP_DIR);
	ಹಿಂತಿರುಗಿ(error ? ಖಾಲಿ : ಮಾರ್ಗ);
}

#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_MKDTEMP) */
