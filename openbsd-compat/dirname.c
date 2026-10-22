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

#അന്തര്ഭാവ "includes.h"
#ifndef HAVE_DIRNAME

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <string.h>

അക്ഷരം *
dirname(സ്ഥിരം അക്ഷരം *path)
{
	സ്ഥിതം അക്ഷരം dname[MAXPATHLEN];
	size_t len;
	സ്ഥിരം അക്ഷരം *endp;

	/* Empty or NULL string gets treated as "." */
	എങ്കിൽ (path == ശൂന്യ || *path == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		തിരികെ (dname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	ആകുമ്പോൾ (endp > path && *endp == '/')
		endp--;

	/* Find the start of the dir */
	ആകുമ്പോൾ (endp > path && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	എങ്കിൽ (endp == path) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		തിരികെ (dname);
	} അല്ലെങ്കിൽ {
		/* Move forward past the separating slashes */
		ചെയ്യുക {
			endp--;
		} ആകുമ്പോൾ (endp > path && *endp == '/');
	}

	len = endp - path + 1;
	എങ്കിൽ (len >= വലുപ്പം(dname)) {
		errno = ENAMETOOLONG;
		തിരികെ (ശൂന്യ);
	}
	memcpy(dname, path, len);
	dname[len] = '\0';
	തിരികെ (dname);
}
#endif
