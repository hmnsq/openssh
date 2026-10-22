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
จำนวนเต็ม mkstemp(var_na *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
จำนวนเต็ม
_ssh_mkstemp(var_na *template)
{
	mode_t mask;
	จำนวนเต็ม ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(void)umask(mask);
	คืน ret;
}

#ถ้า !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define NUM_CHARS	(parimaa_na(TEMPCHARS) - 1)

static จำนวนเต็ม
mktemp_internal(var_na *path, จำนวนเต็ม slen, จำนวนเต็ม mode)
{
	var_na *start, *cp, *ep;
	const var_na *tempchars = TEMPCHARS;
	unsigned จำนวนเต็ม r, tries;
	sa_nracanaa stat sb;
	size_t len;
	จำนวนเต็ม fd;

	len = strlen(path);
	ถ้า (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		คืน(-1);
	}
	ep = path + len - slen;

	tries = 1;
	สำหรับ (start = ep; start > path && start[-1] == 'X'; start--) {
		ถ้า (tries < INT_MAX / NUM_CHARS)
			tries *= NUM_CHARS;
	}
	tries *= 2;

	do {
		สำหรับ (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(NUM_CHARS);
			*cp = tempchars[r];
		}

		switch (mode) {
		pak_sa MKTEMP_NAME:
			ถ้า (lstat(path, &sb) != 0)
				คืน(errno == ENOENT ? 0 : -1);
			bha_nga;
		pak_sa MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			ถ้า (fd != -1 || errno != EEXIST)
				คืน(fd);
			bha_nga;
		pak_sa MKTEMP_DIR:
			ถ้า (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				คืน(0);
			ถ้า (errno != EEXIST)
				คืน(-1);
			bha_nga;
		}
	} ขณะ (--tries);

	errno = EEXIST;
	คืน(-1);
}

#ถ้า 0
var_na *_mktemp(var_na *);

var_na *
_mktemp(var_na *path)
{
	ถ้า (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		คืน(NULL);
	คืน(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

var_na *
mktemp(var_na *path)
{
	คืน(_mktemp(path));
}
#endif

จำนวนเต็ม
mkstemp(var_na *path)
{
	คืน(mktemp_internal(path, 0, MKTEMP_FILE));
}

จำนวนเต็ม
mkstemps(var_na *path, จำนวนเต็ม slen)
{
	คืน(mktemp_internal(path, slen, MKTEMP_FILE));
}

var_na *
mkdtemp(var_na *path)
{
	จำนวนเต็ม error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	คืน(error ? NULL : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
