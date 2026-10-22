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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <ctype.h>
#অন্তর্ভাৱ <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
পূর্ণাঙ্ক mkstemp(ৱর্ণ *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
পূর্ণাঙ্ক
_ssh_mkstemp(ৱর্ণ *template)
{
	mode_t mask;
	পূর্ণাঙ্ক ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(শূন্য)umask(mask);
	ঘূৰাই ret;
}

#যদি !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define অঙ্ক_CHARS	(পরিমাণ(TEMPCHARS) - 1)

স্থির পূর্ণাঙ্ক
mktemp_internal(ৱর্ণ *path, পূর্ণাঙ্ক slen, পূর্ণাঙ্ক mode)
{
	ৱর্ণ *start, *cp, *ep;
	ধ্রুৱ ৱর্ণ *tempchars = TEMPCHARS;
	unsigned পূর্ণাঙ্ক r, tries;
	সংরচনা stat sb;
	size_t len;
	পূর্ণাঙ্ক fd;

	len = strlen(path);
	যদি (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		ঘূৰাই(-1);
	}
	ep = path + len - slen;

	tries = 1;
	বাবে (start = ep; start > path && start[-1] == 'X'; start--) {
		যদি (tries < INT_MAX / অঙ্ক_CHARS)
			tries *= অঙ্ক_CHARS;
	}
	tries *= 2;

	কৰা {
		বাবে (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(অঙ্ক_CHARS);
			*cp = tempchars[r];
		}

		ৱিকল্প (mode) {
		পক্ষ MKTEMP_NAME:
			যদি (lstat(path, &sb) != 0)
				ঘূৰাই(errno == ENOENT ? 0 : -1);
			ভঙ্গ;
		পক্ষ MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			যদি (fd != -1 || errno != EEXIST)
				ঘূৰাই(fd);
			ভঙ্গ;
		পক্ষ MKTEMP_DIR:
			যদি (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				ঘূৰাই(0);
			যদি (errno != EEXIST)
				ঘূৰাই(-1);
			ভঙ্গ;
		}
	} যেতিয়ালৈ (--tries);

	errno = EEXIST;
	ঘূৰাই(-1);
}

#যদি 0
ৱর্ণ *_mktemp(ৱর্ণ *);

ৱর্ণ *
_mktemp(ৱর্ণ *path)
{
	যদি (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		ঘূৰাই(রিক্ত);
	ঘূৰাই(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

ৱর্ণ *
mktemp(ৱর্ণ *path)
{
	ঘূৰাই(_mktemp(path));
}
#endif

পূর্ণাঙ্ক
mkstemp(ৱর্ণ *path)
{
	ঘূৰাই(mktemp_internal(path, 0, MKTEMP_FILE));
}

পূর্ণাঙ্ক
mkstemps(ৱর্ণ *path, পূর্ণাঙ্ক slen)
{
	ঘূৰাই(mktemp_internal(path, slen, MKTEMP_FILE));
}

ৱর্ণ *
mkdtemp(ৱর্ণ *path)
{
	পূর্ণাঙ্ক error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	ঘূৰাই(error ? রিক্ত : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
