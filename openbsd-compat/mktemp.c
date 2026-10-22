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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <limits.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <ctype.h>
#شامل <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
صحیح mkstemp(نویسه *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
صحیح
_ssh_mkstemp(نویسه *template)
{
	mode_t mask;
	صحیح ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(تهی)umask(mask);
	بازگشت ret;
}

#اگر !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define رقم_CHARS	(اندازه(TEMPCHARS) - 1)

ایستا صحیح
mktemp_internal(نویسه *path, صحیح slen, صحیح mode)
{
	نویسه *start, *cp, *ep;
	ثابت نویسه *tempchars = TEMPCHARS;
	unsigned صحیح r, tries;
	ساختار stat sb;
	size_t len;
	صحیح fd;

	len = strlen(path);
	اگر (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		بازگشت(-1);
	}
	ep = path + len - slen;

	tries = 1;
	برای (start = ep; start > path && start[-1] == 'X'; start--) {
		اگر (tries < INT_MAX / رقم_CHARS)
			tries *= رقم_CHARS;
	}
	tries *= 2;

	انجامبده {
		برای (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(رقم_CHARS);
			*cp = tempchars[r];
		}

		انتخاب (mode) {
		حالت MKTEMP_NAME:
			اگر (lstat(path, &sb) != 0)
				بازگشت(errno == ENOENT ? 0 : -1);
			بشکن;
		حالت MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			اگر (fd != -1 || errno != EEXIST)
				بازگشت(fd);
			بشکن;
		حالت MKTEMP_DIR:
			اگر (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				بازگشت(0);
			اگر (errno != EEXIST)
				بازگشت(-1);
			بشکن;
		}
	} وقتی (--tries);

	errno = EEXIST;
	بازگشت(-1);
}

#اگر 0
نویسه *_mktemp(نویسه *);

نویسه *
_mktemp(نویسه *path)
{
	اگر (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		بازگشت(پوچ);
	بازگشت(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

نویسه *
mktemp(نویسه *path)
{
	بازگشت(_mktemp(path));
}
#endif

صحیح
mkstemp(نویسه *path)
{
	بازگشت(mktemp_internal(path, 0, MKTEMP_FILE));
}

صحیح
mkstemps(نویسه *path, صحیح slen)
{
	بازگشت(mktemp_internal(path, slen, MKTEMP_FILE));
}

نویسه *
mkdtemp(نویسه *path)
{
	صحیح error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	بازگشت(error ? پوچ : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
