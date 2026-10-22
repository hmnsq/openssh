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

#અન્તર્ભાવ "includes.h"
#ifndef HAVE_BASENAME
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <string.h>

અક્ષર *
basename(અચલ અક્ષર *path)
{
	સ્થિર અક્ષર bname[MAXPATHLEN];
	size_t len;
	અચલ અક્ષર *endp, *startp;

	/* Empty or NULL string gets treated as "." */
	જો (path == ખાલી || *path == '\0') {
		bname[0] = '.';
		bname[1] = '\0';
		પાછા (bname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	જ્યારે (endp > path && *endp == '/')
		endp--;

	/* All slashes becomes "/" */
	જો (endp == path && *endp == '/') {
		bname[0] = '/';
		bname[1] = '\0';
		પાછા (bname);
	}

	/* Find the start of the base */
	startp = endp;
	જ્યારે (startp > path && *(startp - 1) != '/')
		startp--;

	len = endp - startp + 1;
	જો (len >= કદ(bname)) {
		errno = ENAMETOOLONG;
		પાછા (ખાલી);
	}
	memcpy(bname, startp, len);
	bname[len] = '\0';
	પાછા (bname);
}

#endif /* !defined(HAVE_BASENAME) */
