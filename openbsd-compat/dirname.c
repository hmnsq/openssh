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

#অন্তর্ভাব "includes.h"
#ifndef HAVE_DIRNAME

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>

বর্ণ *
dirname(ধ্রুব বর্ণ *path)
{
	স্থির বর্ণ dname[MAXPATHLEN];
	size_t len;
	ধ্রুব বর্ণ *endp;

	/* Empty or NULL string gets treated as "." */
	যদি (path == রিক্ত || *path == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		প্রত্যাগম (dname);
	}

	/* Strip any trailing slashes */
	endp = path + strlen(path) - 1;
	যাবত্ (endp > path && *endp == '/')
		endp--;

	/* Find the start of the dir */
	যাবত্ (endp > path && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	যদি (endp == path) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		প্রত্যাগম (dname);
	} অন্যথা {
		/* Move forward past the separating slashes */
		কুরু {
			endp--;
		} যাবত্ (endp > path && *endp == '/');
	}

	len = endp - path + 1;
	যদি (len >= পরিমাণ(dname)) {
		errno = ENAMETOOLONG;
		প্রত্যাগম (রিক্ত);
	}
	memcpy(dname, path, len);
	dname[len] = '\0';
	প্রত্যাগম (dname);
}
#endif
