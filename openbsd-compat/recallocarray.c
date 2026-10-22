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
#جے_بنا_تعریف HAVE_RECALLOCARRAY

#ضمن <errno.h>
#ضمن <stdlib.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#تعریف_کرو MUL_NO_حد_توں_ودھ ((ناپ_t)1 << (حجم(ناپ_t) * 4))

فراغ *
recallocarray(فراغ *ptr, ناپ_t oldnmemb, ناپ_t newnmemb, ناپ_t ناپ)
{
	ناپ_t oldsize, newsize;
	فراغ *newptr;

	إذا (ptr == عدم)
		أرجع صفر_حافظہ_دیو(newnmemb, ناپ);

	إذا ((newnmemb >= MUL_NO_حد_توں_ودھ || ناپ >= MUL_NO_حد_توں_ودھ) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < ناپ) {
		errno = ENOMEM;
		أرجع عدم;
	}
	newsize = newnmemb * ناپ;

	إذا ((oldnmemb >= MUL_NO_حد_توں_ودھ || ناپ >= MUL_NO_حد_توں_ودھ) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < ناپ) {
		errno = EINVAL;
		أرجع عدم;
	}
	oldsize = oldnmemb * ناپ;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	إذا (newsize <= oldsize) {
		ناپ_t d = oldsize - newsize;

		إذا (d < oldsize / 2 && d < (ناپ_t)getpagesize()) {
			memset((حرف *)ptr + newsize, 0, d);
			أرجع ptr;
		}
	}

	newptr = حافظہ_دیو(newsize);
	إذا (newptr == عدم)
		أرجع عدم;

	إذا (newsize > oldsize) {
		حافظہ_نقل(newptr, ptr, oldsize);
		memset((حرف *)newptr + oldsize, 0, newsize - oldsize);
	} وإلا
		حافظہ_نقل(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	حرر(ptr);

	أرجع newptr;
}
/* DEF_WEAK(recallocarray); */

#جے_انت /* HAVE_RECALLOCARRAY */
