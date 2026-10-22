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

#شامل "includes.h"
#اگر_غیر_تعریف_شدہ HAVE_DIRNAME

#شامل <errno.h>
#شامل <string.h>

حرف *
dirname(ثابت حرف *راستہ)
{
	ساکن حرف dname[MAXPATHLEN];
	سائز_t len;
	ثابت حرف *endp;

	/* Empty or NULL string gets treated as "." */
	اگر (راستہ == تہی || *راستہ == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		واپس (dname);
	}

	/* Strip any trailing slashes */
	endp = راستہ + لڑی_لمبائی(راستہ) - 1;
	جب (endp > راستہ && *endp == '/')
		endp--;

	/* Find the start of the dir */
	جب (endp > راستہ && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	اگر (endp == راستہ) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		واپس (dname);
	} ورنہ {
		/* Move forward past the separating slashes */
		کرو {
			endp--;
		} جب (endp > راستہ && *endp == '/');
	}

	len = endp - راستہ + 1;
	اگر (len >= حجم(dname)) {
		errno = ENAMETOOLONG;
		واپس (تہی);
	}
	حافظہ_نقل(dname, راستہ, len);
	dname[len] = '\0';
	واپس (dname);
}
#اگر_ختم
