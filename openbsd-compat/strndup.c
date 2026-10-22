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
#ಆದರೆ !defined(HAVE_STRNDUP) || defined(BROKEN_STRNDUP)
#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ಅಕ್ಷರ *
strndup(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str, ಗಾತ್ರ_t maxlen)
{
	ಅಕ್ಷರ *copy;
	ಗಾತ್ರ_t len;

	len = strnlen(str, maxlen);
	copy = ಸ್ಮರಣೆ_ಕೊಡು(len + 1);
	ಆದರೆ (copy != ಖಾಲಿ) {
		(ಶೂನ್ಯ)ಸ್ಮರಣೆ_ನಕಲು(copy, str, len);
		copy[len] = '\0';
	}

	ಹಿಂತಿರುಗಿ copy;
}
DEF_WEAK(strndup);
#ಆದರೆ_ಅಂತ್ಯ  /* HAVE_STRNDUP */
