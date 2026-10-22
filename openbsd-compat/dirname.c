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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ifndef HAVE_DIRNAME

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

ଅକ୍ଷର *
dirname(ଅଚଳ ଅକ୍ଷର *path)
{
	ସ୍ଥିର ଅକ୍ଷର dname[MAXPATHLEN];
	size_t len;
	ଅଚଳ ଅକ୍ଷର *endp;

	/* Empty or NULL string gets treated as "." */
	ଯଦି (path == ଖାଲି || *path == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		ଫେରନ୍ତୁ (dname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	ଯେତେବେଳେ (endp > path && *endp == '/')
		endp--;

	/* Find the start of the dir */
	ଯେତେବେଳେ (endp > path && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	ଯଦି (endp == path) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		ଫେରନ୍ତୁ (dname);
	} ଅନ୍ୟଥା {
		/* Move forward past the separating slashes */
		କର {
			endp--;
		} ଯେତେବେଳେ (endp > path && *endp == '/');
	}

	len = endp - path + 1;
	ଯଦି (len >= ଆକାର(dname)) {
		errno = ENAMETOOLONG;
		ଫେରନ୍ତୁ (ଖାଲି);
	}
	memcpy(dname, path, len);
	dname[len] = '\0';
	ଫେରନ୍ତୁ (dname);
}
#endif
