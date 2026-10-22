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

#અન્તર્ભાવ "includes.h"
#ifndef HAVE_DIRNAME

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <string.h>

અક્ષર *
dirname(અચલ અક્ષર *path)
{
	સ્થિર અક્ષર dname[MAXPATHLEN];
	size_t len;
	અચલ અક્ષર *endp;

	/* Empty or NULL string gets treated as "." */
	જો (path == ખાલી || *path == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		પાછા (dname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	જ્યારે (endp > path && *endp == '/')
		endp--;

	/* Find the start of the dir */
	જ્યારે (endp > path && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	જો (endp == path) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		પાછા (dname);
	} નહીંતર {
		/* Move forward past the separating slashes */
		કરો {
			endp--;
		} જ્યારે (endp > path && *endp == '/');
	}

	len = endp - path + 1;
	જો (len >= કદ(dname)) {
		errno = ENAMETOOLONG;
		પાછા (ખાલી);
	}
	memcpy(dname, path, len);
	dname[len] = '\0';
	પાછા (dname);
}
#endif
