/*	$OpenBSD: strnlen.c,v 1.3 2010/06/02 12:58:12 millert Exp $	*/

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

/* OPENBSD ORIGINAL: lib/libc/string/strnlen.c */

#அந்தர்பாவ "includes.h"
#எனில் !defined(HAVE_STRNLEN) || defined(BROKEN_STRNLEN)
#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <string.h>

size_t
strnlen(மாறிலி எழுத்து *str, size_t maxlen)
{
	மாறிலி எழுத்து *cp;

	க்கு (cp = str; maxlen != 0 && *cp != '\0'; cp++, maxlen--)
		;

	திரும்பு (size_t)(cp - str);
}
#endif
