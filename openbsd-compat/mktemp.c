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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <unistd.h>

#ifdef mkstemp
#undef mkstemp
#endif
પૂર્ણાંક mkstemp(અક્ષર *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
પૂર્ણાંક
_ssh_mkstemp(અક્ષર *template)
{
	mode_t mask;
	પૂર્ણાંક ret;

	mask = umask(0177);
	ret = mkstemp(template);
	(શૂન્ય)umask(mask);
	પાછા ret;
}

#જો !defined(HAVE_MKDTEMP)

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define અંક_CHARS	(કદ(TEMPCHARS) - 1)

સ્થિર પૂર્ણાંક
mktemp_internal(અક્ષર *path, પૂર્ણાંક slen, પૂર્ણાંક mode)
{
	અક્ષર *start, *cp, *ep;
	અચલ અક્ષર *tempchars = TEMPCHARS;
	unsigned પૂર્ણાંક r, tries;
	સંરચના stat sb;
	size_t len;
	પૂર્ણાંક fd;

	len = strlen(path);
	જો (len == 0 || slen < 0 || (size_t)slen >= len) {
		errno = EINVAL;
		પાછા(-1);
	}
	ep = path + len - slen;

	tries = 1;
	માટે (start = ep; start > path && start[-1] == 'X'; start--) {
		જો (tries < INT_MAX / અંક_CHARS)
			tries *= અંક_CHARS;
	}
	tries *= 2;

	કરો {
		માટે (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(અંક_CHARS);
			*cp = tempchars[r];
		}

		પસંદગી (mode) {
		સ્થિતિ MKTEMP_NAME:
			જો (lstat(path, &sb) != 0)
				પાછા(errno == ENOENT ? 0 : -1);
			તોડો;
		સ્થિતિ MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			જો (fd != -1 || errno != EEXIST)
				પાછા(fd);
			તોડો;
		સ્થિતિ MKTEMP_DIR:
			જો (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				પાછા(0);
			જો (errno != EEXIST)
				પાછા(-1);
			તોડો;
		}
	} જ્યારે (--tries);

	errno = EEXIST;
	પાછા(-1);
}

#જો 0
અક્ષર *_mktemp(અક્ષર *);

અક્ષર *
_mktemp(અક્ષર *path)
{
	જો (mktemp_internal(path, 0, MKTEMP_NAME) == -1)
		પાછા(ખાલી);
	પાછા(path);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

અક્ષર *
mktemp(અક્ષર *path)
{
	પાછા(_mktemp(path));
}
#endif

પૂર્ણાંક
mkstemp(અક્ષર *path)
{
	પાછા(mktemp_internal(path, 0, MKTEMP_FILE));
}

પૂર્ણાંક
mkstemps(અક્ષર *path, પૂર્ણાંક slen)
{
	પાછા(mktemp_internal(path, slen, MKTEMP_FILE));
}

અક્ષર *
mkdtemp(અક્ષર *path)
{
	પૂર્ણાંક error;

	error = mktemp_internal(path, 0, MKTEMP_DIR);
	પાછા(error ? ખાલી : path);
}

#endif /* !defined(HAVE_MKDTEMP) */
