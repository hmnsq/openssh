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

#جيڪڏهن_وصف_ٿيل mkstemp
#وصف_رد mkstemp
#جيڪڏهن_پورو
صحيح mkstemp(حرف *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
صحيح
_ssh_mkstemp(حرف *سانچو)
{
	گهڻائي_t نقاب;
	صحيح ret;

	نقاب = umask(0177);
	ret = mkstemp(سانچو);
	(فراغ)umask(نقاب);
	أرجع ret;
}

#إذا !defined(HAVE_MKDTEMP)

#وصف_ڪريو MKTEMP_NAME	0
#وصف_ڪريو MKTEMP_FILE	1
#وصف_ڪريو MKTEMP_DIR	2

#وصف_ڪريو TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#وصف_ڪريو انگ_CHARS	(حجم(TEMPCHARS) - 1)

ساكن صحيح
mktemp_اندروني(حرف *رستو, صحيح slen, صحيح گهڻائي)
{
	حرف *شروعات, *cp, *ep;
	ثابت حرف *tempchars = TEMPCHARS;
	بنانشان صحيح r, tries;
	بنية stat sb;
	سائيز_t len;
	صحيح fd;

	len = لڙي_ڊيگهه(رستو);
	إذا (len == 0 || slen < 0 || (سائيز_t)slen >= len) {
		errno = EINVAL;
		أرجع(-1);
	}
	ep = رستو + len - slen;

	tries = 1;
	لكل (شروعات = ep; شروعات > رستو && شروعات[-1] == 'X'; شروعات--) {
		إذا (tries < وڌ_کان_وڌ_عدد / انگ_CHARS)
			tries *= انگ_CHARS;
	}
	tries *= 2;

	افعل {
		لكل (cp = شروعات; cp != ep; cp++) {
			r = arc4random_هڪجهڙو(انگ_CHARS);
			*cp = tempchars[r];
		}

		بدل (گهڻائي) {
		حالة MKTEMP_NAME:
			إذا (lstat(رستو, &sb) != 0)
				أرجع(errno == ENOENT ? 0 : -1);
			اكسر;
		حالة MKTEMP_FILE:
			fd = open(رستو, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			إذا (fd != -1 || errno != EEXIST)
				أرجع(fd);
			اكسر;
		حالة MKTEMP_DIR:
			إذا (mkdir(رستو, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
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
_mktemp(حرف *رستو)
{
	إذا (mktemp_اندروني(رستو, 0, MKTEMP_NAME) == -1)
		أرجع(عدم);
	أرجع(رستو);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

حرف *
mktemp(حرف *رستو)
{
	أرجع(_mktemp(رستو));
}
#جيڪڏهن_پورو

صحيح
mkstemp(حرف *رستو)
{
	أرجع(mktemp_اندروني(رستو, 0, MKTEMP_FILE));
}

صحيح
mkstemps(حرف *رستو, صحيح slen)
{
	أرجع(mktemp_اندروني(رستو, slen, MKTEMP_FILE));
}

حرف *
mkdtemp(حرف *رستو)
{
	صحيح error;

	error = mktemp_اندروني(رستو, 0, MKTEMP_DIR);
	أرجع(error ? عدم : رستو);
}

#جيڪڏهن_پورو /* !defined(HAVE_MKDTEMP) */
