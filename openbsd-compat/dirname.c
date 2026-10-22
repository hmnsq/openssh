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

#ضمن "includes.h"
#جے_بنا_تعریف HAVE_DIRNAME

#ضمن <errno.h>
#ضمن <string.h>

حرف *
dirname(ثابت حرف *رستہ)
{
	ساكن حرف dname[MAXPATHLEN];
	ناپ_t len;
	ثابت حرف *endp;

	/* Empty or NULL string gets treated as "." */
	إذا (رستہ == عدم || *رستہ == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		أرجع (dname);
	}

	/* Strip any trailing slashes */
	endp = رستہ + لڑی_لمبائی(رستہ) - 1;
	طالما (endp > رستہ && *endp == '/')
		endp--;

	/* Find the start of the dir */
	طالما (endp > رستہ && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	إذا (endp == رستہ) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		أرجع (dname);
	} وإلا {
		/* Move forward past the separating slashes */
		افعل {
			endp--;
		} طالما (endp > رستہ && *endp == '/');
	}

	len = endp - رستہ + 1;
	إذا (len >= حجم(dname)) {
		errno = ENAMETOOLONG;
		أرجع (عدم);
	}
	حافظہ_نقل(dname, رستہ, len);
	dname[len] = '\0';
	أرجع (dname);
}
#جے_انت
