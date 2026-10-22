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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ifndef HAVE_RECALLOCARRAY

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define MUL_NO_OVERFLOW ((size_t)1 << (ଆକାର(size_t) * 4))

ଶୂନ୍ୟ *
recallocarray(ଶୂନ୍ୟ *ptr, size_t oldnmemb, size_t newnmemb, size_t size)
{
	size_t oldsize, newsize;
	ଶୂନ୍ୟ *newptr;

	ଯଦି (ptr == ଖାଲି)
		ଫେରନ୍ତୁ calloc(newnmemb, size);

	ଯଦି ((newnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < size) {
		errno = ENOMEM;
		ଫେରନ୍ତୁ ଖାଲି;
	}
	newsize = newnmemb * size;

	ଯଦି ((oldnmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < size) {
		errno = EINVAL;
		ଫେରନ୍ତୁ ଖାଲି;
	}
	oldsize = oldnmemb * size;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	ଯଦି (newsize <= oldsize) {
		size_t d = oldsize - newsize;

		ଯଦି (d < oldsize / 2 && d < (size_t)getpagesize()) {
			memset((ଅକ୍ଷର *)ptr + newsize, 0, d);
			ଫେରନ୍ତୁ ptr;
		}
	}

	newptr = malloc(newsize);
	ଯଦି (newptr == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	ଯଦି (newsize > oldsize) {
		memcpy(newptr, ptr, oldsize);
		memset((ଅକ୍ଷର *)newptr + oldsize, 0, newsize - oldsize);
	} ଅନ୍ୟଥା
		memcpy(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	ମୁକ୍ତ(ptr);

	ଫେରନ୍ତୁ newptr;
}
/* DEF_WEAK(recallocarray); */

#endif /* HAVE_RECALLOCARRAY */
