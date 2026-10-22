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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <ctype.h>
#ضمن <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
صحيح mkstemp(حرف *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
صحيح
_ssh_mkstemp(حرف *template)
{
	mode_t mask;
	صحيح ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(فراغ)umask(mask);
	أرجع ret;
}

#𐡄𐡍 !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define NUM_CHARS	(حجم(TEMPCHARS) - 1)

ساكن صحيح
mktemp_internal(حرف *path, صحيح slen, صحيح mode)
{
	حرف *start, *cp, *ep;
	ثابت حرف *tempchars = TEMPCHARS;
	unsigned صحيح r, tries;
	بنية stat sb;
	size_t len;
	صحيح fd;

	len = strlen(path);
	𐡄𐡍 (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		أرجع(-1);
	}
	ep = path + len - slen;

	tries = 1;
	لكل (start = ep; start > path && start[-1] == 'X'; start--) {
		𐡄𐡍 (tries < INT_MAX / NUM_CHARS)
			tries *= NUM_CHARS;
	}
	tries *= 2;

	𐡏𐡁𐡃 {
		لكل (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(NUM_CHARS);
			*cp = tempchars[r];
		}

		بدل (mode) {
		حالة MKTEMP_NAME:
			𐡄𐡍 (lstat(path, &sb) != 0)
				أرجع(errno == ENOENT ? 0 : -1);
			اكسر;
		حالة MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			𐡄𐡍 (fd != -1 || errno != EEXIST)
				أرجع(fd);
			اكسر;
		حالة MKTEMP_DIR:
			𐡄𐡍 (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				أرجع(0);
			𐡄𐡍 (errno != EEXIST)
				أرجع(-1);
			اكسر;
		}
	} طالما (--tries);

	errno = EEXIST;
	أرجع(-1);
}

#𐡄𐡍 0
حرف *_mktemp(حرف *);

حرف *
_mktemp(حرف *path)
{
	𐡄𐡍 (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		أرجع(عدم);
	أرجع(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

حرف *
mktemp(حرف *path)
{
	أرجع(_mktemp(path));
}
#endif

صحيح
mkstemp(حرف *path)
{
	أرجع(mktemp_internal(path, 0, MKTEMP_FILE));
}

صحيح
mkstemps(حرف *path, صحيح slen)
{
	أرجع(mktemp_internal(path, slen, MKTEMP_FILE));
}

حرف *
mkdtemp(حرف *path)
{
	صحيح error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	أرجع(error ? عدم : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
