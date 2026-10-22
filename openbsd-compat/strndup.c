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

#شامل "includes.h"
#اگر !defined(HAVE_STRNDUP) || defined(BROKEN_STRNDUP)
#شامل <sys/types.h>

#شامل <stddef.h>
#شامل <stdlib.h>
#شامل <string.h>

حرف *
strndup(ثابت حرف *str, سائز_t maxlen)
{
	حرف *copy;
	سائز_t len;

	len = strnlen(str, maxlen);
	copy = حافظہ_دو(len + 1);
	اگر (copy != تہی) {
		(خالی)حافظہ_نقل(copy, str, len);
		copy[len] = '\0';
	}

	واپس copy;
}
DEF_WEAK(strndup);
#اگر_ختم  /* HAVE_STRNDUP */
