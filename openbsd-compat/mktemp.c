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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <limits.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <ctype.h>
#شامل <unistd.h>

#اگر_تعریف_شدہ mkstemp
#تعریف_منسوخ mkstemp
#اگر_ختم
صحیح mkstemp(حرف *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
صحیح
_ssh_mkstemp(حرف *سانچہ)
{
	منوال_t نقاب;
	صحیح ret;

	نقاب = umask(0177);
	ret = mkstemp(سانچہ);
	(خالی)umask(نقاب);
	واپس ret;
}

#اگر !defined(HAVE_MKDTEMP)

#تعریف_کرو MKTEMP_NAME	0
#تعریف_کرو MKTEMP_FILE	1
#تعریف_کرو MKTEMP_DIR	2

#تعریف_کرو TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#تعریف_کرو عدد_CHARS	(حجم(TEMPCHARS) - 1)

ساکن صحیح
mktemp_اندرونی(حرف *راستہ, صحیح slen, صحیح منوال)
{
	حرف *آغاز, *cp, *ep;
	ثابت حرف *tempchars = TEMPCHARS;
	غیرعلامتی صحیح r, tries;
	ساخت stat sb;
	سائز_t len;
	صحیح fd;

	len = لڑی_لمبائی(راستہ);
	اگر (len == 0 || slen < 0 || (سائز_t)slen >= len) {
		errno = EINVAL;
		واپس(-1);
	}
	ep = راستہ + len - slen;

	tries = 1;
	برائے (آغاز = ep; آغاز > راستہ && آغاز[-1] == 'X'; آغاز--) {
		اگر (tries < زیادہ_سے_زیادہ_عدد / عدد_CHARS)
			tries *= عدد_CHARS;
	}
	tries *= 2;

	کرو {
		برائے (cp = آغاز; cp != ep; cp++) {
			r = arc4random_یکساں(عدد_CHARS);
			*cp = tempchars[r];
		}

		انتخاب (منوال) {
		حالت MKTEMP_NAME:
			اگر (lstat(راستہ, &sb) != 0)
				واپس(errno == ENOENT ? 0 : -1);
			توڑو;
		حالت MKTEMP_FILE:
			fd = open(راستہ, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			اگر (fd != -1 || errno != EEXIST)
				واپس(fd);
			توڑو;
		حالت MKTEMP_DIR:
			اگر (mkdir(راستہ, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				واپس(0);
			اگر (errno != EEXIST)
				واپس(-1);
			توڑو;
		}
	} جب (--tries);

	errno = EEXIST;
	واپس(-1);
}

#اگر 0
حرف *_mktemp(حرف *);

حرف *
_mktemp(حرف *راستہ)
{
	اگر (mktemp_اندرونی(راستہ, 0, MKTEMP_NAME) == -1)
		واپس(تہی);
	واپس(راستہ);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

حرف *
mktemp(حرف *راستہ)
{
	واپس(_mktemp(راستہ));
}
#اگر_ختم

صحیح
mkstemp(حرف *راستہ)
{
	واپس(mktemp_اندرونی(راستہ, 0, MKTEMP_FILE));
}

صحیح
mkstemps(حرف *راستہ, صحیح slen)
{
	واپس(mktemp_اندرونی(راستہ, slen, MKTEMP_FILE));
}

حرف *
mkdtemp(حرف *راستہ)
{
	صحیح error;

	error = mktemp_اندرونی(راستہ, 0, MKTEMP_DIR);
	واپس(error ? تہی : راستہ);
}

#اگر_ختم /* !defined(HAVE_MKDTEMP) */
