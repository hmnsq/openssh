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

#که_تعریف_شوی mkstemp
#تعریف_لغوه mkstemp
#د_که_پای
صحيح mkstemp(حرف *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
صحيح
_ssh_mkstemp(حرف *کينډۍ)
{
	ډېرپېښ_t ماسک;
	صحيح ret;

	ماسک = umask(0177);
	ret = mkstemp(کينډۍ);
	(فراغ)umask(ماسک);
	أرجع ret;
}

#إذا !defined(HAVE_MKDTEMP)

#تعریف_کړه MKTEMP_NAME	0
#تعریف_کړه MKTEMP_FILE	1
#تعریف_کړه MKTEMP_DIR	2

#تعریف_کړه TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#تعریف_کړه عدد_CHARS	(حجم(TEMPCHARS) - 1)

ساكن صحيح
mktemp_دننی(حرف *لار, صحيح slen, صحيح ډېرپېښ)
{
	حرف *پیل, *cp, *ep;
	ثابت حرف *tempchars = TEMPCHARS;
	بینښه صحيح r, tries;
	بنية stat sb;
	اندازه_t len;
	صحيح fd;

	len = مزي_اوږدوالی(لار);
	إذا (len == 0 || slen < 0 || (اندازه_t)slen >= len) {
		errno = EINVAL;
		أرجع(-1);
	}
	ep = لار + len - slen;

	tries = 1;
	لكل (پیل = ep; پیل > لار && پیل[-1] == 'X'; پیل--) {
		إذا (tries < لوی_عدد / عدد_CHARS)
			tries *= عدد_CHARS;
	}
	tries *= 2;

	افعل {
		لكل (cp = پیل; cp != ep; cp++) {
			r = arc4random_یوشان(عدد_CHARS);
			*cp = tempchars[r];
		}

		بدل (ډېرپېښ) {
		حالة MKTEMP_NAME:
			إذا (lstat(لار, &sb) != 0)
				أرجع(errno == ENOENT ? 0 : -1);
			اكسر;
		حالة MKTEMP_FILE:
			fd = open(لار, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			إذا (fd != -1 || errno != EEXIST)
				أرجع(fd);
			اكسر;
		حالة MKTEMP_DIR:
			إذا (mkdir(لار, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				أرجع(0);
			إذا (errno != EEXIST)
				أرجع(-1);
			اكسر;
		}
	} طالما (--tries);

	errno = EEXIST;
	أرجع(-1);
}

#إذا 0
حرف *_mktemp(حرف *);

حرف *
_mktemp(حرف *لار)
{
	إذا (mktemp_دننی(لار, 0, MKTEMP_NAME) == -1)
		أرجع(عدم);
	أرجع(لار);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

حرف *
mktemp(حرف *لار)
{
	أرجع(_mktemp(لار));
}
#د_که_پای

صحيح
mkstemp(حرف *لار)
{
	أرجع(mktemp_دننی(لار, 0, MKTEMP_FILE));
}

صحيح
mkstemps(حرف *لار, صحيح slen)
{
	أرجع(mktemp_دننی(لار, slen, MKTEMP_FILE));
}

حرف *
mkdtemp(حرف *لار)
{
	صحيح error;

	error = mktemp_دننی(لار, 0, MKTEMP_DIR);
	أرجع(error ? عدم : لار);
}

#د_که_پای /* !defined(HAVE_MKDTEMP) */
