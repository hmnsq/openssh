/*	$OpenBSD: recallocarray.c,v 1.1 2017/03/06 18:44:21 otto Exp $	*/
/*
 * Copyright (c) 2008, 2017 Otto Moerbeek <otto@drijf.net>
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

/* OPENBSD ORIGINAL: lib/libc/stdlib/recallocarray.c */

#அந்தர்பாவ "includes.h"
#ifndef HAVE_RECALLOCARRAY

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW ((size_t)1 << (அளவு(size_t) * 4))

வெறுமை *
recallocarray(வெறுமை *ptr, size_t oldnmemb, size_t newnmemb, size_t size)
{
	size_t oldsize, newsize;
	வெறுமை *newptr;

	எனில் (ptr == வெற்று)
		திரும்பு calloc(newnmemb, size);

	எனில் ((newnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < size) {
		errno = ENOMEM;
		திரும்பு வெற்று;
	}
	newsize = newnmemb * size;

	எனில் ((oldnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < size) {
		errno = EINVAL;
		திரும்பு வெற்று;
	}
	oldsize = oldnmemb * size;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	எனில் (newsize <= oldsize) {
		size_t d = oldsize - newsize;

		எனில் (d < oldsize / 2 && d < (size_t)getpagesize()) {
			memset((எழுத்து *)ptr + newsize, 0, d);
			திரும்பு ptr;
		}
	}

	newptr = malloc(newsize);
	எனில் (newptr == வெற்று)
		திரும்பு வெற்று;

	எனில் (newsize > oldsize) {
		memcpy(newptr, ptr, oldsize);
		memset((எழுத்து *)newptr + oldsize, 0, newsize - oldsize);
	} இல்லையெனில்
		memcpy(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	விடுவி(ptr);

	திரும்பு newptr;
}
/* DEF_WEAK(recallocarray); */

#endif /* HAVE_RECALLOCARRAY */
