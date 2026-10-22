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
#यदि_अपरिभाषितम् HAVE_DIRNAME

#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>

वर्ण *
dirname(ध्रुव वर्ण *मार्गः)
{
	स्थिर वर्ण dname[MAXPATHLEN];
	आकार_t len;
	ध्रुव वर्ण *endp;

	/* Empty or NULL string gets treated as "." */
	यदि (मार्गः == रिक्त || *मार्गः == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		प्रत्यागम (dname);
	}

	/* Strip any trailing slashes */
	endp = मार्गः + वाक्यदैर्घ्यम्(मार्गः) - 1;
	यावत् (endp > मार्गः && *endp == '/')
		endp--;

	/* Find the start of the dir */
	यावत् (endp > मार्गः && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	यदि (endp == मार्गः) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		प्रत्यागम (dname);
	} अन्यथा {
		/* Move forward past the separating slashes */
		कुरु {
			endp--;
		} यावत् (endp > मार्गः && *endp == '/');
	}

	len = endp - मार्गः + 1;
	यदि (len >= परिमाण(dname)) {
		errno = ENAMETOOLONG;
		प्रत्यागम (रिक्त);
	}
	स्मृतिं_प्रतिलिख(dname, मार्गः, len);
	dname[len] = '\0';
	प्रत्यागम (dname);
}
#यदि_अन्तः
