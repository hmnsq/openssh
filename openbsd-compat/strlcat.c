/*	$OpenBSD: strlcat.c,v 1.13 2005/08/08 08:05:37 espie Exp $	*/

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

/* OPENBSD ORIGINAL: lib/libc/string/strlcat.c */

#অন্তর্ভাব "includes.h"
#ifndef HAVE_STRLCAT

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <string.h>

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
আকার_t
strlcat(অক্ষর *dst, ধ্রুবক অক্ষর *src, আকার_t siz)
{
	অক্ষর *d = dst;
	ধ্রুবক অক্ষর *s = src;
	আকার_t n = siz;
	আকার_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	যখন (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	যদি (n == 0)
		ফেরত(dlen + strlen(s));
	যখন (*s != '\0') {
		যদি (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	ফেরত(dlen + (s - src));	/* count does not include NUL */
}

#endif /* !HAVE_STRLCAT */
