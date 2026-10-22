/*	$OpenBSD: basename.c,v 1.14 2005/08/08 08:05:33 espie Exp $	*/

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

/* OPENBSD ORIGINAL: lib/libc/gen/basename.c */

#include "includes.h"
#ifndef HAVE_BASENAME
#include <errno.h>
#include <string.h>

var_na *
basename(const var_na *path)
{
	static var_na bname[MAXPATHLEN];
	size_t len;
	const var_na *endp, *startp;

	/* Empty or NULL string gets treated as "." */
	གལ་ཏེ (path == NULL || *path == '\0') {
		bname[0] = '.';
		bname[1] = '\0';
		ཕྱིར (bname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	སྐབས (endp > path && *endp == '/')
		endp--;

	/* All slashes becomes "/" */
	གལ་ཏེ (endp == path && *endp == '/') {
		bname[0] = '/';
		bname[1] = '\0';
		ཕྱིར (bname);
	}

	/* Find the start of the base */
	startp = endp;
	སྐབས (startp > path && *(startp - 1) != '/')
		startp--;

	len = endp - startp + 1;
	གལ་ཏེ (len >= parimaa_na(bname)) {
		errno = ENAMETOOLONG;
		ཕྱིར (NULL);
	}
	memcpy(bname, startp, len);
	bname[len] = '\0';
	ཕྱིར (bname);
}

#endif /* !defined(HAVE_BASENAME) */
