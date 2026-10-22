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

#అన్తర్భావ "includes.h"
#నిర్వచితం_కాకపోతే HAVE_STRLCPY

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <string.h>

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
కొలత_t
strlcpy(అక్షరం *dst, స్థిరరాశి అక్షరం *src, కొలత_t siz)
{
	అక్షరం *d = dst;
	స్థిరరాశి అక్షరం *s = src;
	కొలత_t n = siz;

	/* Copy as many bytes as will fit */
	ఒకవేళ (n != 0) {
		అయితే (--n != 0) {
			ఒకవేళ ((*d++ = *s++) == '\0')
				ఆపు;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	ఒకవేళ (n == 0) {
		ఒకవేళ (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		అయితే (*s++)
			;
	}

	తిరిగి(s - src - 1);	/* count does not include NUL */
}

#అయితే_ముగింపు /* !HAVE_STRLCPY */
