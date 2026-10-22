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

#അന്തര്ഭാവ "includes.h"
#ifndef HAVE_BASENAME
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <string.h>

അക്ഷരം *
basename(സ്ഥിരം അക്ഷരം *path)
{
	സ്ഥിതം അക്ഷരം bname[MAXPATHLEN];
	size_t len;
	സ്ഥിരം അക്ഷരം *endp, *startp;

	/* Empty or NULL string gets treated as "." */
	എങ്കിൽ (path == ശൂന്യ || *path == '\0') {
		bname[0] = '.';
		bname[1] = '\0';
		തിരികെ (bname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	ആകുമ്പോൾ (endp > path && *endp == '/')
		endp--;

	/* All slashes becomes "/" */
	എങ്കിൽ (endp == path && *endp == '/') {
		bname[0] = '/';
		bname[1] = '\0';
		തിരികെ (bname);
	}

	/* Find the start of the base */
	startp = endp;
	ആകുമ്പോൾ (startp > path && *(startp - 1) != '/')
		startp--;

	len = endp - startp + 1;
	എങ്കിൽ (len >= വലുപ്പം(bname)) {
		errno = ENAMETOOLONG;
		തിരികെ (ശൂന്യ);
	}
	memcpy(bname, startp, len);
	bname[len] = '\0';
	തിരികെ (bname);
}

#endif /* !defined(HAVE_BASENAME) */
