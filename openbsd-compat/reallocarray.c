/*	$OpenBSD: reallocarray.c,v 1.2 2014/12/08 03:45:00 bcook Exp $	*/
/*
 * Copyright (c) 2008 Otto Moerbeek <otto@drijf.net>
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

/* OPENBSD ORIGINAL: lib/libc/stdlib/reallocarray.c */

#அந்தர்பாவ "includes.h"
#ifndef HAVE_REALLOCARRAY

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW	((size_t)1 << (அளவு(size_t) * 4))

வெறுமை *
reallocarray(வெறுமை *optr, size_t nmemb, size_t size)
{
	எனில் ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    nmemb > 0 && SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		திரும்பு வெற்று;
	}
	திரும்பு realloc(optr, size * nmemb);
}
#endif /* HAVE_REALLOCARRAY */
