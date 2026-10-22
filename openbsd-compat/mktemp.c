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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
পূর্ণসংখ্যা mkstemp(অক্ষর *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
পূর্ণসংখ্যা
_ssh_mkstemp(অক্ষর *template)
{
	mode_t mask;
	পূর্ণসংখ্যা ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(শূন্য)umask(mask);
	ফেরত ret;
}

#যদি !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define অঙ্ক_CHARS	(আকার(TEMPCHARS) - 1)

স্থির পূর্ণসংখ্যা
mktemp_internal(অক্ষর *path, পূর্ণসংখ্যা slen, পূর্ণসংখ্যা mode)
{
	অক্ষর *start, *cp, *ep;
	ধ্রুবক অক্ষর *tempchars = TEMPCHARS;
	unsigned পূর্ণসংখ্যা r, tries;
	কাঠামো stat sb;
	আকার_t len;
	পূর্ণসংখ্যা fd;

	len = strlen(path);
	যদি (len == 0 || slen < 0 || (আকার_t)slen >= len) {
		errno = EINVAL;
		ফেরত(-1);
	}
	ep = path + len - slen;

	tries = 1;
	জন্য (start = ep; start > path && start[-1] == 'X'; start--) {
		যদি (tries < INT_MAX / অঙ্ক_CHARS)
			tries *= অঙ্ক_CHARS;
	}
	tries *= 2;

	করো {
		জন্য (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(অঙ্ক_CHARS);
			*cp = tempchars[r];
		}

		নির্বাচন (mode) {
		ক্ষেত্র MKTEMP_NAME:
			যদি (lstat(path, &sb) != 0)
				ফেরত(errno == ENOENT ? 0 : -1);
			বিরতি;
		ক্ষেত্র MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			যদি (fd != -1 || errno != EEXIST)
				ফেরত(fd);
			বিরতি;
		ক্ষেত্র MKTEMP_DIR:
			যদি (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				ফেরত(0);
			যদি (errno != EEXIST)
				ফেরত(-1);
			বিরতি;
		}
	} যখন (--tries);

	errno = EEXIST;
	ফেরত(-1);
}

#যদি 0
অক্ষর *_mktemp(অক্ষর *);

অক্ষর *
_mktemp(অক্ষর *path)
{
	যদি (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		ফেরত(ফাঁকা);
	ফেরত(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

অক্ষর *
mktemp(অক্ষর *path)
{
	ফেরত(_mktemp(path));
}
#endif

পূর্ণসংখ্যা
mkstemp(অক্ষর *path)
{
	ফেরত(mktemp_internal(path, 0, MKTEMP_FILE));
}

পূর্ণসংখ্যা
mkstemps(অক্ষর *path, পূর্ণসংখ্যা slen)
{
	ফেরত(mktemp_internal(path, slen, MKTEMP_FILE));
}

অক্ষর *
mkdtemp(অক্ষর *path)
{
	পূর্ণসংখ্যা error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	ফেরত(error ? ফাঁকা : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
