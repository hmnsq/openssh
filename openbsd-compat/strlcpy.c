/*	$OpenBSD: strlcpy.c,v 1.11 2006/05/05 15:27:38 millert Exp $	*/

/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
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

/* OPENBSD ORIGINAL: lib/libc/string/strlcpy.c */

#شامل "includes.h"
#اگر_غیر_تعریف_شدہ HAVE_STRLCPY

#شامل <sys/types.h>
#شامل <string.h>

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
سائز_t
strlcpy(حرف *dst, ثابت حرف *src, سائز_t siz)
{
	حرف *d = dst;
	ثابت حرف *s = src;
	سائز_t n = siz;

	/* Copy as many bytes as will fit */
	اگر (n != 0) {
		جب (--n != 0) {
			اگر ((*d++ = *s++) == '\0')
				توڑو;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	اگر (n == 0) {
		اگر (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		جب (*s++)
			;
	}

	واپس(s - src - 1);	/* count does not include NUL */
}

#اگر_ختم /* !HAVE_STRLCPY */
