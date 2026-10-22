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

वर्ण *
basename(अचर वर्ण *path)
{
	स्थिर वर्ण bname[MAXPATHLEN];
	माप_प्रकार len;
	अचर वर्ण *endp, *startp;

	/* Empty or NULL string gets treated as "." */
	यदि (path == रिक्त || *path == '\0') {
		bname[0] = '.';
		bname[1] = '\0';
		फर्काऊ (bname);
	}

	/* Strip any trailing slashes */
	endp = path + म_माप(path) - 1;
	जबसम्म (endp > path && *endp == '/')
		endp--;

	/* All slashes becomes "/" */
	यदि (endp == path && *endp == '/') {
		bname[0] = '/';
		bname[1] = '\0';
		फर्काऊ (bname);
	}

	/* Find the start of the base */
	startp = endp;
	जबसम्म (startp > path && *(startp - 1) != '/')
		startp--;

	len = endp - startp + 1;
	यदि (len >= परिमाण(bname)) {
		त्रुटि_सं = ENAMETOOLONG;
		फर्काऊ (रिक्त);
	}
	स_नकल(bname, startp, len);
	bname[len] = '\0';
	फर्काऊ (bname);
}

#endif /* !defined(HAVE_BASENAME) */
