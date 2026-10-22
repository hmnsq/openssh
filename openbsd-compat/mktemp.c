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
පූර්ණ_සංඛ්‍යා mkstemp(var_na *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
පූර්ණ_සංඛ්‍යා
_ssh_mkstemp(var_na *template)
{
	mode_t mask;
	පූර්ණ_සංඛ්‍යා ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(void)umask(mask);
	ආපසු ret;
}

#නම් !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define NUM_CHARS	(parimaa_na(TEMPCHARS) - 1)

static පූර්ණ_සංඛ්‍යා
mktemp_internal(var_na *path, පූර්ණ_සංඛ්‍යා slen, පූර්ණ_සංඛ්‍යා mode)
{
	var_na *start, *cp, *ep;
	const var_na *tempchars = TEMPCHARS;
	unsigned පූර්ණ_සංඛ්‍යා r, tries;
	sa_nracanaa stat sb;
	size_t len;
	පූර්ණ_සංඛ්‍යා fd;

	len = strlen(path);
	නම් (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		ආපසු(-1);
	}
	ep = path + len - slen;

	tries = 1;
	සඳහා (start = ep; start > path && start[-1] == 'X'; start--) {
		නම් (tries < INT_MAX / NUM_CHARS)
			tries *= NUM_CHARS;
	}
	tries *= 2;

	do {
		සඳහා (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(NUM_CHARS);
			*cp = tempchars[r];
		}

		switch (mode) {
		pak_sa MKTEMP_NAME:
			නම් (lstat(path, &sb) != 0)
				ආපසු(errno == ENOENT ? 0 : -1);
			bha_nga;
		pak_sa MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			නම් (fd != -1 || errno != EEXIST)
				ආපසු(fd);
			bha_nga;
		pak_sa MKTEMP_DIR:
			නම් (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				ආපසු(0);
			නම් (errno != EEXIST)
				ආපසු(-1);
			bha_nga;
		}
	} අතරතුර (--tries);

	errno = EEXIST;
	ආපසු(-1);
}

#නම් 0
var_na *_mktemp(var_na *);

var_na *
_mktemp(var_na *path)
{
	නම් (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		ආපසු(NULL);
	ආපසු(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

var_na *
mktemp(var_na *path)
{
	ආපසු(_mktemp(path));
}
#endif

පූර්ණ_සංඛ්‍යා
mkstemp(var_na *path)
{
	ආපසු(mktemp_internal(path, 0, MKTEMP_FILE));
}

පූර්ණ_සංඛ්‍යා
mkstemps(var_na *path, පූර්ණ_සංඛ්‍යා slen)
{
	ආපසු(mktemp_internal(path, slen, MKTEMP_FILE));
}

var_na *
mkdtemp(var_na *path)
{
	පූර්ණ_සංඛ්‍යා error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	ආපසු(error ? NULL : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
