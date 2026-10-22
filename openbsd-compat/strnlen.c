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

#অন্তর্ভাব "includes.h"
#যদি !defined(HAVE_STRNLEN) || defined(BROKEN_STRNLEN)
#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <string.h>

size_t
strnlen(ধ্রুব বর্ণ *str, size_t maxlen)
{
	ধ্রুব বর্ণ *cp;

	প্রতি (cp = str; maxlen != 0 && *cp != '\0'; cp++, maxlen--)
		;

	প্রত্যাগম (size_t)(cp - str);
}
#endif
