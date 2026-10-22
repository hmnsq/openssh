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

#अन्तर्भाव "includes.h"
#ifndef HAVE_DIRNAME

#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>

अक्षर *
स_नाम(स्थिरांक अक्षर *path)
{
	स्थिर अक्षर dname[MAXPATHLEN];
	माप_प्रकार len;
	स्थिरांक अक्षर *endp;

	/* Empty or NULL string gets treated as "." */
	जर (path == रिक्त || *path == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		परत (dname);
	}

	/* Strip any trailing slashes */
	endp = path + म_माप(path) - 1;
	पर्यंत (endp > path && *endp == '/')
		endp--;

	/* Find the start of the dir */
	पर्यंत (endp > path && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	जर (endp == path) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		परत (dname);
	} अन्यथा {
		/* Move forward past the separating slashes */
		करा {
			endp--;
		} पर्यंत (endp > path && *endp == '/');
	}

	len = endp - path + 1;
	जर (len >= आकार(dname)) {
		त्रुटि_सं = ENAMETOOLONG;
		परत (रिक्त);
	}
	स_नकल(dname, path, len);
	dname[len] = '\0';
	परत (dname);
}
#endif
