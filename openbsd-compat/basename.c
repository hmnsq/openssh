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

#समावेश "includes.h"
#अगर_अघोषित HAVE_BASENAME
#समावेश <errno.h>
#समावेश <string.h>

अक्षर *
basename(स्थिर अक्षर *path)
{
	अटल अक्षर bname[MAXPATHLEN];
	माप_प्रकार len;
	स्थिर अक्षर *endp, *startp;

	/* Empty or NULL string gets treated as "." */
	अगर (path == शून्य || *path == '\0') {
		bname[0] = '.';
		bname[1] = '\0';
		वापस (bname);
	}

	/* Strip any trailing slashes */
	endp = path + म_माप(path) - 1;
	जबतक (endp > path && *endp == '/')
		endp--;

	/* All slashes becomes "/" */
	अगर (endp == path && *endp == '/') {
		bname[0] = '/';
		bname[1] = '\0';
		वापस (bname);
	}

	/* Find the start of the base */
	startp = endp;
	जबतक (startp > path && *(startp - 1) != '/')
		startp--;

	len = endp - startp + 1;
	अगर (len >= माप(bname)) {
		त्रुटि_सं = ENAMETOOLONG;
		वापस (शून्य);
	}
	स_नकल(bname, startp, len);
	bname[len] = '\0';
	वापस (bname);
}

#पूर्ण_अगर /* !defined(HAVE_BASENAME) */
