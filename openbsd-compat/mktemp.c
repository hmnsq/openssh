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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
整数 mkstemp(char *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
整数
_ssh_mkstemp(char *template)
{
	mode_t mask;
	整数 ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(void)umask(mask);
	返回 ret;
}

#如果 !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define NUM_CHARS	(sizeof(TEMPCHARS) - 1)

static 整数
mktemp_internal(char *path, 整数 slen, 整数 mode)
{
	char *start, *cp, *ep;
	const char *tempchars = TEMPCHARS;
	unsigned 整数 r, tries;
	struct stat sb;
	size_t len;
	整数 fd;

	len = strlen(path);
	如果 (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		返回(-1);
	}
	ep = path + len - slen;

	tries = 1;
	为 (start = ep; start > path && start[-1] == 'X'; start--) {
		如果 (tries < INT_MAX / NUM_CHARS)
			tries *= NUM_CHARS;
	}
	tries *= 2;

	do {
		为 (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(NUM_CHARS);
			*cp = tempchars[r];
		}

		switch (mode) {
		case MKTEMP_NAME:
			如果 (lstat(path, &sb) != 0)
				返回(errno == ENOENT ? 0 : -1);
			break;
		case MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			如果 (fd != -1 || errno != EEXIST)
				返回(fd);
			break;
		case MKTEMP_DIR:
			如果 (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				返回(0);
			如果 (errno != EEXIST)
				返回(-1);
			break;
		}
	} 当 (--tries);

	errno = EEXIST;
	返回(-1);
}

#如果 0
char *_mktemp(char *);

char *
_mktemp(char *path)
{
	如果 (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		返回(NULL);
	返回(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

char *
mktemp(char *path)
{
	返回(_mktemp(path));
}
#endif

整数
mkstemp(char *path)
{
	返回(mktemp_internal(path, 0, MKTEMP_FILE));
}

整数
mkstemps(char *path, 整数 slen)
{
	返回(mktemp_internal(path, slen, MKTEMP_FILE));
}

char *
mkdtemp(char *path)
{
	整数 error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	返回(error ? NULL : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
