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

#समावेश "includes.h"
#अगर_अघोषित HAVE_DIRNAME

#समावेश <errno.h>
#समावेश <string.h>

अक्षर *
स_नाम(स्थिर अक्षर *path)
{
	अटल अक्षर dname[MAXPATHLEN];
	माप_प्रकार len;
	स्थिर अक्षर *endp;

	/* Empty or NULL string gets treated as "." */
	अगर (path == शून्य || *path == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		वापस (dname);
	}

	/* Strip any trailing slashes */
	endp = path + म_माप(path) - 1;
	जबतक (endp > path && *endp == '/')
		endp--;

	/* Find the start of the dir */
	जबतक (endp > path && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	अगर (endp == path) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		वापस (dname);
	} अन्यथा {
		/* Move forward past the separating slashes */
		करो {
			endp--;
		} जबतक (endp > path && *endp == '/');
	}

	len = endp - path + 1;
	अगर (len >= माप(dname)) {
		त्रुटि_सं = ENAMETOOLONG;
		वापस (शून्य);
	}
	स_नकल(dname, path, len);
	dname[len] = '\0';
	वापस (dname);
}
#पूर्ण_अगर
