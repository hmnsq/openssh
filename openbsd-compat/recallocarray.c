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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_RECALLOCARRAY

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUL_NO_ਉਛਾਲ ((ਮਾਪ_t)1 << (ਆਕਾਰ(ਮਾਪ_t) * 4))

ਖਾਲੀ *
recallocarray(ਖਾਲੀ *ptr, ਮਾਪ_t oldnmemb, ਮਾਪ_t newnmemb, ਮਾਪ_t ਮਾਪ)
{
	ਮਾਪ_t oldsize, newsize;
	ਖਾਲੀ *newptr;

	ਜੇ (ptr == ਨਿਰਾ)
		ਵਾਪਸ ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(newnmemb, ਮਾਪ);

	ਜੇ ((newnmemb >= MUL_NO_ਉਛਾਲ || ਮਾਪ >= MUL_NO_ਉਛਾਲ) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < ਮਾਪ) {
		errno = ENOMEM;
		ਵਾਪਸ ਨਿਰਾ;
	}
	newsize = newnmemb * ਮਾਪ;

	ਜੇ ((oldnmemb >= MUL_NO_ਉਛਾਲ || ਮਾਪ >= MUL_NO_ਉਛਾਲ) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < ਮਾਪ) {
		errno = EINVAL;
		ਵਾਪਸ ਨਿਰਾ;
	}
	oldsize = oldnmemb * ਮਾਪ;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	ਜੇ (newsize <= oldsize) {
		ਮਾਪ_t d = oldsize - newsize;

		ਜੇ (d < oldsize / 2 && d < (ਮਾਪ_t)getpagesize()) {
			memset((ਅੱਖਰ *)ptr + newsize, 0, d);
			ਵਾਪਸ ptr;
		}
	}

	newptr = ਸਮ੍ਰਿਤੀ_ਦਿਓ(newsize);
	ਜੇ (newptr == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	ਜੇ (newsize > oldsize) {
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(newptr, ptr, oldsize);
		memset((ਅੱਖਰ *)newptr + oldsize, 0, newsize - oldsize);
	} ਨਹੀਂਤਾਂ
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	ਮੁਕਤ(ptr);

	ਵਾਪਸ newptr;
}
/* DEF_WEAK(recallocarray); */

#ਜੇ_ਅੰਤ /* HAVE_RECALLOCARRAY */
