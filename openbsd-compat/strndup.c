/*	$OpenBSD: strndup.c,v 1.2 2015/08/31 02:53:57 guenther Exp $	*/

/*
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಯದಿ !defined(HAVE_STRNDUP) || defined(BROKEN_STRNDUP)
#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ವರ್ಣ *
strndup(ಧ್ರುವ ವರ್ಣ *str, size_t maxlen)
{
	ವರ್ಣ *copy;
	size_t len;

	len = strnlen(str, maxlen);
	copy = malloc(len + 1);
	ಯದಿ (copy != ರಿಕ್ತ) {
		(ಶೂನ್ಯ)memcpy(copy, str, len);
		copy[len] = '\0';
	}

	ಪ್ರತ್ಯಾಗಮ copy;
}
DEF_WEAK(strndup);
#endif  /* HAVE_STRNDUP */
