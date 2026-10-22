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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ifndef HAVE_RECALLOCARRAY

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW ((size_t)1 << (ಪರಿಮಾಣ(size_t) * 4))

ಶೂನ್ಯ *
recallocarray(ಶೂನ್ಯ *ptr, size_t oldnmemb, size_t newnmemb, size_t size)
{
	size_t oldsize, newsize;
	ಶೂನ್ಯ *newptr;

	ಯದಿ (ptr == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ calloc(newnmemb, size);

	ಯದಿ ((newnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < size) {
		errno = ENOMEM;
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	newsize = newnmemb * size;

	ಯದಿ ((oldnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < size) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	oldsize = oldnmemb * size;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	ಯದಿ (newsize <= oldsize) {
		size_t d = oldsize - newsize;

		ಯದಿ (d < oldsize / 2 && d < (size_t)getpagesize()) {
			memset((ವರ್ಣ *)ptr + newsize, 0, d);
			ಪ್ರತ್ಯಾಗಮ ptr;
		}
	}

	newptr = malloc(newsize);
	ಯದಿ (newptr == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	ಯದಿ (newsize > oldsize) {
		memcpy(newptr, ptr, oldsize);
		memset((ವರ್ಣ *)newptr + oldsize, 0, newsize - oldsize);
	} ಅನ್ಯಥಾ
		memcpy(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	ಮುಕ್ತ(ptr);

	ಪ್ರತ್ಯಾಗಮ newptr;
}
/* DEF_WEAK(recallocarray); */

#endif /* HAVE_RECALLOCARRAY */
