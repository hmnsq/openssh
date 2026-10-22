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

#अन्तर्भाव "includes.h"
#ifndef HAVE_BASENAME
#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>

अक्षर *
basename(स्थिरांक अक्षर *path)
{
	स्थिर अक्षर bname[MAXPATHLEN];
	माप_प्रकार len;
	स्थिरांक अक्षर *endp, *startp;

	/* Empty or NULL string gets treated as "." */
	जर (path == रिक्त || *path == '\0') {
		bname[0] = '.';
		bname[1] = '\0';
		परत (bname);
	}

	/* Strip any trailing slashes */
	endp = path + म_माप(path) - 1;
	पर्यंत (endp > path && *endp == '/')
		endp--;

	/* All slashes becomes "/" */
	जर (endp == path && *endp == '/') {
		bname[0] = '/';
		bname[1] = '\0';
		परत (bname);
	}

	/* Find the start of the base */
	startp = endp;
	पर्यंत (startp > path && *(startp - 1) != '/')
		startp--;

	len = endp - startp + 1;
	जर (len >= आकार(bname)) {
		त्रुटि_सं = ENAMETOOLONG;
		परत (रिक्त);
	}
	स_नकल(bname, startp, len);
	bname[len] = '\0';
	परत (bname);
}

#endif /* !defined(HAVE_BASENAME) */
