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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
முழு mkstemp(எழுத்து *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
முழு
_ssh_mkstemp(எழுத்து *template)
{
	mode_t mask;
	முழு ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(வெறுமை)umask(mask);
	திரும்பு ret;
}

#எனில் !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define இலக்கம்_CHARS	(அளவு(TEMPCHARS) - 1)

நிலையான முழு
mktemp_internal(எழுத்து *path, முழு slen, முழு mode)
{
	எழுத்து *start, *cp, *ep;
	மாறிலி எழுத்து *tempchars = TEMPCHARS;
	unsigned முழு r, tries;
	கட்டமைப்பு stat sb;
	size_t len;
	முழு fd;

	len = strlen(path);
	எனில் (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		திரும்பு(-1);
	}
	ep = path + len - slen;

	tries = 1;
	க்கு (start = ep; start > path && start[-1] == 'X'; start--) {
		எனில் (tries < INT_MAX / இலக்கம்_CHARS)
			tries *= இலக்கம்_CHARS;
	}
	tries *= 2;

	செய் {
		க்கு (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(இலக்கம்_CHARS);
			*cp = tempchars[r];
		}

		தேர்வு (mode) {
		நிலை MKTEMP_NAME:
			எனில் (lstat(path, &sb) != 0)
				திரும்பு(errno == ENOENT ? 0 : -1);
			நிறுத்து;
		நிலை MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			எனில் (fd != -1 || errno != EEXIST)
				திரும்பு(fd);
			நிறுத்து;
		நிலை MKTEMP_DIR:
			எனில் (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				திரும்பு(0);
			எனில் (errno != EEXIST)
				திரும்பு(-1);
			நிறுத்து;
		}
	} போது (--tries);

	errno = EEXIST;
	திரும்பு(-1);
}

#எனில் 0
எழுத்து *_mktemp(எழுத்து *);

எழுத்து *
_mktemp(எழுத்து *path)
{
	எனில் (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		திரும்பு(வெற்று);
	திரும்பு(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

எழுத்து *
mktemp(எழுத்து *path)
{
	திரும்பு(_mktemp(path));
}
#endif

முழு
mkstemp(எழுத்து *path)
{
	திரும்பு(mktemp_internal(path, 0, MKTEMP_FILE));
}

முழு
mkstemps(எழுத்து *path, முழு slen)
{
	திரும்பு(mktemp_internal(path, slen, MKTEMP_FILE));
}

எழுத்து *
mkdtemp(எழுத்து *path)
{
	முழு error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	திரும்பு(error ? வெற்று : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
