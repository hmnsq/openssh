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

#അന്തര്ഭാവ "includes.h"
#എങ്കിൽ !defined(HAVE_STRNDUP) || defined(BROKEN_STRNDUP)
#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

അക്ഷരം *
strndup(സ്ഥിരം അക്ഷരം *str, size_t maxlen)
{
	അക്ഷരം *copy;
	size_t len;

	len = strnlen(str, maxlen);
	copy = malloc(len + 1);
	എങ്കിൽ (copy != ശൂന്യ) {
		(ശൂന്യം)memcpy(copy, str, len);
		copy[len] = '\0';
	}

	തിരികെ copy;
}
DEF_WEAK(strndup);
#endif  /* HAVE_STRNDUP */
