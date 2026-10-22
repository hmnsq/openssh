/*	$OpenBSD: dirname.c,v 1.13 2005/08/08 08:05:33 espie Exp $	*/

/*
 * Copyright (c) 1997, 2004 Todd C. Miller <Todd.Miller@courtesan.com>
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

/* OPENBSD ORIGINAL: lib/libc/gen/dirname.c */

#অন্তর্ভাব "includes.h"
#ifndef HAVE_DIRNAME

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>

অক্ষর *
dirname(ধ্রুবক অক্ষর *path)
{
	স্থির অক্ষর dname[MAXPATHLEN];
	আকার_t len;
	ধ্রুবক অক্ষর *endp;

	/* Empty or NULL string gets treated as "." */
	যদি (path == ফাঁকা || *path == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		ফেরত (dname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	যখন (endp > path && *endp == '/')
		endp--;

	/* Find the start of the dir */
	যখন (endp > path && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	যদি (endp == path) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		ফেরত (dname);
	} অন্যথা {
		/* Move forward past the separating slashes */
		করো {
			endp--;
		} যখন (endp > path && *endp == '/');
	}

	len = endp - path + 1;
	যদি (len >= আকার(dname)) {
		errno = ENAMETOOLONG;
		ফেরত (ফাঁকা);
	}
	memcpy(dname, path, len);
	dname[len] = '\0';
	ফেরত (dname);
}
#endif
