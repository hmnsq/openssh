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

#ضمن "includes.h"
#إذا !defined(HAVE_STRNDUP) || defined(BROKEN_STRNDUP)
#ضمن <sys/types.h>

#ضمن <stddef.h>
#ضمن <stdlib.h>
#ضمن <string.h>

حرف *
strndup(ثابت حرف *str, اندازه_t maxlen)
{
	حرف *copy;
	اندازه_t len;

	len = strnlen(str, maxlen);
	copy = حافظه_بده(len + 1);
	إذا (copy != عدم) {
		(فراغ)کپی_حافظه(copy, str, len);
		copy[len] = '\0';
	}

	أرجع copy;
}
DEF_WEAK(strndup);
#پایان_اگر  /* HAVE_STRNDUP */
