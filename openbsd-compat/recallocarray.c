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

#ضمن "includes.h"
#ifndef HAVE_RECALLOCARRAY

#ضمن <errno.h>
#ضمن <stdlib.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW ((size_t)1 << (حجم(size_t) * 4))

فراغ *
recallocarray(فراغ *ptr, size_t oldnmemb, size_t newnmemb, size_t size)
{
	size_t oldsize, newsize;
	فراغ *newptr;

	𐤀𐤌 (ptr == عدم)
		أرجع calloc(newnmemb, size);

	𐤀𐤌 ((newnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < size) {
		errno = ENOMEM;
		أرجع عدم;
	}
	newsize = newnmemb * size;

	𐤀𐤌 ((oldnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < size) {
		errno = EINVAL;
		أرجع عدم;
	}
	oldsize = oldnmemb * size;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	𐤀𐤌 (newsize <= oldsize) {
		size_t d = oldsize - newsize;

		𐤀𐤌 (d < oldsize / 2 && d < (size_t)getpagesize()) {
			memset((حرف *)ptr + newsize, 0, d);
			أرجع ptr;
		}
	}

	newptr = malloc(newsize);
	𐤀𐤌 (newptr == عدم)
		أرجع عدم;

	𐤀𐤌 (newsize > oldsize) {
		memcpy(newptr, ptr, oldsize);
		memset((حرف *)newptr + oldsize, 0, newsize - oldsize);
	} وإلا
		memcpy(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	حرر(ptr);

	أرجع newptr;
}
/* DEF_WEAK(recallocarray); */

#endif /* HAVE_RECALLOCARRAY */
