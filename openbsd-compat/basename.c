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

#அந்தர்பாவ "includes.h"
#ifndef HAVE_BASENAME
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <string.h>

எழுத்து *
basename(மாறிலி எழுத்து *path)
{
	நிலையான எழுத்து bname[MAXPATHLEN];
	size_t len;
	மாறிலி எழுத்து *endp, *startp;

	/* Empty or NULL string gets treated as "." */
	எனில் (path == வெற்று || *path == '\0') {
		bname[0] = '.';
		bname[1] = '\0';
		திரும்பு (bname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	போது (endp > path && *endp == '/')
		endp--;

	/* All slashes becomes "/" */
	எனில் (endp == path && *endp == '/') {
		bname[0] = '/';
		bname[1] = '\0';
		திரும்பு (bname);
	}

	/* Find the start of the base */
	startp = endp;
	போது (startp > path && *(startp - 1) != '/')
		startp--;

	len = endp - startp + 1;
	எனில் (len >= அளவு(bname)) {
		errno = ENAMETOOLONG;
		திரும்பு (வெற்று);
	}
	memcpy(bname, startp, len);
	bname[len] = '\0';
	திரும்பு (bname);
}

#endif /* !defined(HAVE_BASENAME) */
