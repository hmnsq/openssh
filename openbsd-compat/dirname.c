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
#اگر_تعریف_نشده HAVE_DIRNAME

#ضمن <errno.h>
#ضمن <string.h>

حرف *
dirname(ثابت حرف *مسیر)
{
	ساكن حرف dname[MAXPATHLEN];
	اندازه_t len;
	ثابت حرف *endp;

	/* Empty or NULL string gets treated as "." */
	إذا (مسیر == عدم || *مسیر == '\0') {
		dname[0] = '.';
		dname[1] = '\0';
		أرجع (dname);
	}

	/* Strip any trailing slashes */
	endp = مسیر + طول_رشته(مسیر) - 1;
	طالما (endp > مسیر && *endp == '/')
		endp--;

	/* Find the start of the dir */
	طالما (endp > مسیر && *endp != '/')
		endp--;

	/* Either the dir is "/" or there are no slashes */
	إذا (endp == مسیر) {
		dname[0] = *endp == '/' ? '/' : '.';
		dname[1] = '\0';
		أرجع (dname);
	} وإلا {
		/* Move forward past the separating slashes */
		افعل {
			endp--;
		} طالما (endp > مسیر && *endp == '/');
	}

	len = endp - مسیر + 1;
	إذا (len >= حجم(dname)) {
		errno = ENAMETOOLONG;
		أرجع (عدم);
	}
	کپی_حافظه(dname, مسیر, len);
	dname[len] = '\0';
	أرجع (dname);
}
#پایان_اگر
