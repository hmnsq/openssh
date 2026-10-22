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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <ctype.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే mkstemp
#నిర్వచనం_రద్దు mkstemp
#అయితే_ముగింపు
పూర్ణాంకం mkstemp(అక్షరం *);

/*
 * From glibc man page: 'In glibc versions 2.06 and earlier, the file is
 * created with permissions 0666, that is, read and write for all users.'
 * Provide a wrapper to make sure the mask is reasonable (POSIX requires
 * mode 0600, so mask off any other bits).
 */
పూర్ణాంకం
_ssh_mkstemp(అక్షరం *మూస)
{
	బహుళకం_t ముసుగు;
	పూర్ణాంకం ret;

	ముసుగు = umask(0177);
	ret = mkstemp(మూస);
	(శూన్య)umask(ముసుగు);
	తిరిగి ret;
}

#ఒకవేళ !defined(HAVE_MKDTEMP)

#నిర్వచించు MKTEMP_NAME	0
#నిర్వచించు MKTEMP_FILE	1
#నిర్వచించు MKTEMP_DIR	2

#నిర్వచించు TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#నిర్వచించు అంకె_CHARS	(పరిమాణం(TEMPCHARS) - 1)

స్థిర పూర్ణాంకం
mktemp_అంతర్గత(అక్షరం *మార్గం, పూర్ణాంకం slen, పూర్ణాంకం బహుళకం)
{
	అక్షరం *ప్రారంభం, *cp, *ep;
	స్థిరరాశి అక్షరం *tempchars = TEMPCHARS;
	గుర్తులేని పూర్ణాంకం r, tries;
	నిర్మాణం stat sb;
	కొలత_t len;
	పూర్ణాంకం fd;

	len = అక్షరశ్రేణి_పొడవు(మార్గం);
	ఒకవేళ (len == 0 || slen < 0 || (కొలత_t)slen >= len) {
		errno = EINVAL;
		తిరిగి(-1);
	}
	ep = మార్గం + len - slen;

	tries = 1;
	కొరకు (ప్రారంభం = ep; ప్రారంభం > మార్గం && ప్రారంభం[-1] == 'X'; ప్రారంభం--) {
		ఒకవేళ (tries < గరిష్ఠ_పూర్ణాంకం / అంకె_CHARS)
			tries *= అంకె_CHARS;
	}
	tries *= 2;

	చేయి {
		కొరకు (cp = ప్రారంభం; cp != ep; cp++) {
			r = arc4random_ఏకరీతి(అంకె_CHARS);
			*cp = tempchars[r];
		}

		ఎంపిక (బహుళకం) {
		స్థితి MKTEMP_NAME:
			ఒకవేళ (lstat(మార్గం, &sb) != 0)
				తిరిగి(errno == ENOENT ? 0 : -1);
			ఆపు;
		స్థితి MKTEMP_FILE:
			fd = open(మార్గం, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			ఒకవేళ (fd != -1 || errno != EEXIST)
				తిరిగి(fd);
			ఆపు;
		స్థితి MKTEMP_DIR:
			ఒకవేళ (mkdir(మార్గం, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				తిరిగి(0);
			ఒకవేళ (errno != EEXIST)
				తిరిగి(-1);
			ఆపు;
		}
	} అయితే (--tries);

	errno = EEXIST;
	తిరిగి(-1);
}

#ఒకవేళ 0
అక్షరం *_mktemp(అక్షరం *);

అక్షరం *
_mktemp(అక్షరం *మార్గం)
{
	ఒకవేళ (mktemp_అంతర్గత(మార్గం, 0, MKTEMP_NAME) == -1)
		తిరిగి(ఖాళీ);
	తిరిగి(మార్గం);
}

__warn_references(mktemp,
    "warning: mktemp() possibly used unsafely; consider using mkstemp()");

అక్షరం *
mktemp(అక్షరం *మార్గం)
{
	తిరిగి(_mktemp(మార్గం));
}
#అయితే_ముగింపు

పూర్ణాంకం
mkstemp(అక్షరం *మార్గం)
{
	తిరిగి(mktemp_అంతర్గత(మార్గం, 0, MKTEMP_FILE));
}

పూర్ణాంకం
mkstemps(అక్షరం *మార్గం, పూర్ణాంకం slen)
{
	తిరిగి(mktemp_అంతర్గత(మార్గం, slen, MKTEMP_FILE));
}

అక్షరం *
mkdtemp(అక్షరం *మార్గం)
{
	పూర్ణాంకం error;

	error = mktemp_అంతర్గత(మార్గం, 0, MKTEMP_DIR);
	తిరిగి(error ? ఖాళీ : మార్గం);
}

#అయితే_ముగింపు /* !defined(HAVE_MKDTEMP) */
