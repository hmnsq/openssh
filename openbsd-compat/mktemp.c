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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
ପୂର୍ଣ୍ଣସଂଖ୍ୟା mkstemp(ଅକ୍ଷର *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
_ssh_mkstemp(ଅକ୍ଷର *template)
{
	mode_t mask;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(ଶୂନ୍ୟ)umask(mask);
	ଫେରନ୍ତୁ ret;
}

#ଯଦି !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define ଅଙ୍କ_CHARS	(ଆକାର(TEMPCHARS) - 1)

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mktemp_internal(ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା slen, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode)
{
	ଅକ୍ଷର *start, *cp, *ep;
	ଅଚଳ ଅକ୍ଷର *tempchars = TEMPCHARS;
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, tries;
	ସଂରଚନା stat sb;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd;

	len = strlen(path);
	ଯଦି (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		ଫେରନ୍ତୁ(-1);
	}
	ep = path + len - slen;

	tries = 1;
	ପାଇଁ (start = ep; start > path && start[-1] == 'X'; start--) {
		ଯଦି (tries < INT_MAX / ଅଙ୍କ_CHARS)
			tries *= ଅଙ୍କ_CHARS;
	}
	tries *= 2;

	କର {
		ପାଇଁ (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(ଅଙ୍କ_CHARS);
			*cp = tempchars[r];
		}

		ବାଛ (mode) {
		ସ୍ଥିତି MKTEMP_NAME:
			ଯଦି (lstat(path, &sb) != 0)
				ଫେରନ୍ତୁ(errno == ENOENT ? 0 : -1);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			ଯଦି (fd != -1 || errno != EEXIST)
				ଫେରନ୍ତୁ(fd);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି MKTEMP_DIR:
			ଯଦି (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				ଫେରନ୍ତୁ(0);
			ଯଦି (errno != EEXIST)
				ଫେରନ୍ତୁ(-1);
			ଭାଙ୍ଗ;
		}
	} ଯେତେବେଳେ (--tries);

	errno = EEXIST;
	ଫେରନ୍ତୁ(-1);
}

#ଯଦି 0
ଅକ୍ଷର *_mktemp(ଅକ୍ଷର *);

ଅକ୍ଷର *
_mktemp(ଅକ୍ଷର *path)
{
	ଯଦି (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		ଫେରନ୍ତୁ(ଖାଲି);
	ଫେରନ୍ତୁ(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

ଅକ୍ଷର *
mktemp(ଅକ୍ଷର *path)
{
	ଫେରନ୍ତୁ(_mktemp(path));
}
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mkstemp(ଅକ୍ଷର *path)
{
	ଫେରନ୍ତୁ(mktemp_internal(path, 0, MKTEMP_FILE));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mkstemps(ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା slen)
{
	ଫେରନ୍ତୁ(mktemp_internal(path, slen, MKTEMP_FILE));
}

ଅକ୍ଷର *
mkdtemp(ଅକ୍ଷର *path)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	ଫେରନ୍ତୁ(error ? ଖାଲି : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
