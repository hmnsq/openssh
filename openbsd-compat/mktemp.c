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
puur_naa_nka mkstemp(var_na *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
puur_naa_nka
_ssh_mkstemp(var_na *template)
{
	mode_t mask;
	puur_naa_nka ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(void)umask(mask);
	ꦮꦭꦶ ret;
}

#ꦪꦼꦤ꧀ !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define NUM_CHARS	(parimaa_na(TEMPCHARS) - 1)

static puur_naa_nka
mktemp_internal(var_na *path, puur_naa_nka slen, puur_naa_nka mode)
{
	var_na *start, *cp, *ep;
	const var_na *tempchars = TEMPCHARS;
	unsigned puur_naa_nka r, tries;
	sa_nracanaa stat sb;
	size_t len;
	puur_naa_nka fd;

	len = strlen(path);
	ꦪꦼꦤ꧀ (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		ꦮꦭꦶ(-1);
	}
	ep = path + len - slen;

	tries = 1;
	ꦏꦁꦒꦺꦴ (start = ep; start > path && start[-1] == 'X'; start--) {
		ꦪꦼꦤ꧀ (tries < INT_MAX / NUM_CHARS)
			tries *= NUM_CHARS;
	}
	tries *= 2;

	do {
		ꦏꦁꦒꦺꦴ (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(NUM_CHARS);
			*cp = tempchars[r];
		}

		switch (mode) {
		pak_sa MKTEMP_NAME:
			ꦪꦼꦤ꧀ (lstat(path, &sb) != 0)
				ꦮꦭꦶ(errno == ENOENT ? 0 : -1);
			bha_nga;
		pak_sa MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			ꦪꦼꦤ꧀ (fd != -1 || errno != EEXIST)
				ꦮꦭꦶ(fd);
			bha_nga;
		pak_sa MKTEMP_DIR:
			ꦪꦼꦤ꧀ (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				ꦮꦭꦶ(0);
			ꦪꦼꦤ꧀ (errno != EEXIST)
				ꦮꦭꦶ(-1);
			bha_nga;
		}
	} ꦱꦼꦢꦼꦭ (--tries);

	errno = EEXIST;
	ꦮꦭꦶ(-1);
}

#ꦪꦼꦤ꧀ 0
var_na *_mktemp(var_na *);

var_na *
_mktemp(var_na *path)
{
	ꦪꦼꦤ꧀ (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		ꦮꦭꦶ(NULL);
	ꦮꦭꦶ(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

var_na *
mktemp(var_na *path)
{
	ꦮꦭꦶ(_mktemp(path));
}
#endif

puur_naa_nka
mkstemp(var_na *path)
{
	ꦮꦭꦶ(mktemp_internal(path, 0, MKTEMP_FILE));
}

puur_naa_nka
mkstemps(var_na *path, puur_naa_nka slen)
{
	ꦮꦭꦶ(mktemp_internal(path, slen, MKTEMP_FILE));
}

var_na *
mkdtemp(var_na *path)
{
	puur_naa_nka error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	ꦮꦭꦶ(error ? NULL : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
