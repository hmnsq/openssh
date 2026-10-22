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

#اگر_تعریف_شده mkstemp
#لغو_تعریف mkstemp
#پایان_اگر
صحيح mkstemp(حرف *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
صحيح
_ssh_mkstemp(حرف *قالب)
{
	نما_t ماسک;
	صحيح ret;

	ماسک = umask(0177);
	ret = mkstemp(قالب);
	(فراغ)umask(ماسک);
	أرجع ret;
}

#إذا !defined(HAVE_MKDTEMP)

#تعریف_کن MKTEMP_NAME	0
#تعریف_کن MKTEMP_FILE	1
#تعریف_کن MKTEMP_DIR	2

#تعریف_کن TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#تعریف_کن رقم_CHARS	(حجم(TEMPCHARS) - 1)

ساكن صحيح
mktemp_داخلی(حرف *مسیر, صحيح slen, صحيح نما)
{
	حرف *شروع, *cp, *ep;
	ثابت حرف *tempchars = TEMPCHARS;
	بیعلامت صحيح r, tries;
	بنية stat sb;
	اندازه_t len;
	صحيح fd;

	len = طول_رشته(مسیر);
	إذا (len == 0 || slen < 0 || (اندازه_t)slen >= len) {
		errno = EINVAL;
		أرجع(-1);
	}
	ep = مسیر + len - slen;

	tries = 1;
	لكل (شروع = ep; شروع > مسیر && شروع[-1] == 'X'; شروع--) {
		إذا (tries < بیشترین_صحیح / رقم_CHARS)
			tries *= رقم_CHARS;
	}
	tries *= 2;

	افعل {
		لكل (cp = شروع; cp != ep; cp++) {
			r = arc4random_یکنواخت(رقم_CHARS);
			*cp = tempchars[r];
		}

		بدل (نما) {
		حالة MKTEMP_NAME:
			إذا (lstat(مسیر, &sb) != 0)
				أرجع(errno == ENOENT ? 0 : -1);
			اكسر;
		حالة MKTEMP_FILE:
			fd = open(مسیر, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			إذا (fd != -1 || errno != EEXIST)
				أرجع(fd);
			اكسر;
		حالة MKTEMP_DIR:
			إذا (mkdir(مسیر, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
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
_mktemp(حرف *مسیر)
{
	إذا (mktemp_داخلی(مسیر, 0, MKTEMP_NAME) == -1)
		أرجع(عدم);
	أرجع(مسیر);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

حرف *
mktemp(حرف *مسیر)
{
	أرجع(_mktemp(مسیر));
}
#پایان_اگر

صحيح
mkstemp(حرف *مسیر)
{
	أرجع(mktemp_داخلی(مسیر, 0, MKTEMP_FILE));
}

صحيح
mkstemps(حرف *مسیر, صحيح slen)
{
	أرجع(mktemp_داخلی(مسیر, slen, MKTEMP_FILE));
}

حرف *
mkdtemp(حرف *مسیر)
{
	صحيح error;

	error = mktemp_داخلی(مسیر, 0, MKTEMP_DIR);
	أرجع(error ? عدم : مسیر);
}

#پایان_اگر /* !defined(HAVE_MKDTEMP) */
