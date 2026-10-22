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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ !defined(HAVE_STRNLEN) || defined(BROKEN_STRNLEN)
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਮਾਪ_t
strnlen(ਅਚਲ ਅੱਖਰ *str, ਮਾਪ_t maxlen)
{
	ਅਚਲ ਅੱਖਰ *cp;

	ਲਈ (cp = str; maxlen != 0 && *cp != '\0'; cp++, maxlen--)
		;

	ਵਾਪਸ (ਮਾਪ_t)(cp - str);
}
#ਜੇ_ਅੰਤ
