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

#अन्तर्भाव "includes.h"
#ifndef HAVE_STRLCAT

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <string.h>

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
माप_प्रकार
strlcat(वर्ण *dst, ध्रुव वर्ण *src, माप_प्रकार siz)
{
	वर्ण *d = dst;
	ध्रुव वर्ण *s = src;
	माप_प्रकार n = siz;
	माप_प्रकार dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	यावत् (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	यदि (n == 0)
		प्रत्यागम(dlen + म_माप(s));
	यावत् (*s != '\0') {
		यदि (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	प्रत्यागम(dlen + (s - src));	/* count does not include NUL */
}

#endif /* !HAVE_STRLCAT */
