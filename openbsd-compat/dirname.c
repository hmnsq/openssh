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

#include "includes.h"
#ifndef HAVE_DIRNAME

#include <errno.h>
#include <string.h>

char *
dirname(const char *path)
{
	static char dname[MAXPATHLEN];
	size_t len;
	const char *endp;

	/* Empty or NULL string gets treated as "." */
	만약 (path == NULL || *path == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		반환 (dname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	동안 (endp > path && *endp == '/')
		endp--;

	/* Find the start of the dir */
	동안 (endp > path && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	만약 (endp == path) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		반환 (dname);
	} 아니면 {
		/* Move forward past the separating slashes */
		do {
			endp--;
		} 동안 (endp > path && *endp == '/');
	}

	len = endp - path + 1;
	만약 (len >= sizeof(dname)) {
		errno = ENAMETOOLONG;
		반환 (NULL);
	}
	memcpy(dname, path, len);
	dname[len] = '\0';
	반환 (dname);
}
#endif
