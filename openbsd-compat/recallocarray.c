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

#അന്തര്ഭാവ "includes.h"
#ifndef HAVE_RECALLOCARRAY

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW ((size_t)1 << (വലുപ്പം(size_t) * 4))

ശൂന്യം *
recallocarray(ശൂന്യം *ptr, size_t oldnmemb, size_t newnmemb, size_t size)
{
	size_t oldsize, newsize;
	ശൂന്യം *newptr;

	എങ്കിൽ (ptr == ശൂന്യ)
		തിരികെ calloc(newnmemb, size);

	എങ്കിൽ ((newnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < size) {
		errno = ENOMEM;
		തിരികെ ശൂന്യ;
	}
	newsize = newnmemb * size;

	എങ്കിൽ ((oldnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < size) {
		errno = EINVAL;
		തിരികെ ശൂന്യ;
	}
	oldsize = oldnmemb * size;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	എങ്കിൽ (newsize <= oldsize) {
		size_t d = oldsize - newsize;

		എങ്കിൽ (d < oldsize / 2 && d < (size_t)getpagesize()) {
			memset((അക്ഷരം *)ptr + newsize, 0, d);
			തിരികെ ptr;
		}
	}

	newptr = malloc(newsize);
	എങ്കിൽ (newptr == ശൂന്യ)
		തിരികെ ശൂന്യ;

	എങ്കിൽ (newsize > oldsize) {
		memcpy(newptr, ptr, oldsize);
		memset((അക്ഷരം *)newptr + oldsize, 0, newsize - oldsize);
	} അല്ലെങ്കിൽ
		memcpy(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	സ്വതന്ത്രം(ptr);

	തിരികെ newptr;
}
/* DEF_WEAK(recallocarray); */

#endif /* HAVE_RECALLOCARRAY */
