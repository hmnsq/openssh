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
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_RECALLOCARRAY

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#ವ್ಯಾಖ್ಯಾನಿಸು MUL_NO_ಅತಿಪ್ರವಾಹ ((ಗಾತ್ರ_t)1 << (ಗಾತ್ರ(ಗಾತ್ರ_t) * 4))

ಶೂನ್ಯ *
recallocarray(ಶೂನ್ಯ *ptr, ಗಾತ್ರ_t oldnmemb, ಗಾತ್ರ_t newnmemb, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಗಾತ್ರ_t oldsize, newsize;
	ಶೂನ್ಯ *newptr;

	ಆದರೆ (ptr == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(newnmemb, ಗಾತ್ರ_2);

	ಆದರೆ ((newnmemb >= MUL_NO_ಅತಿಪ್ರವಾಹ || ಗಾತ್ರ_2 >= MUL_NO_ಅತಿಪ್ರವಾಹ) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < ಗಾತ್ರ_2) {
		errno = ENOMEM;
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	newsize = newnmemb * ಗಾತ್ರ_2;

	ಆದರೆ ((oldnmemb >= MUL_NO_ಅತಿಪ್ರವಾಹ || ಗಾತ್ರ_2 >= MUL_NO_ಅತಿಪ್ರವಾಹ) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < ಗಾತ್ರ_2) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	oldsize = oldnmemb * ಗಾತ್ರ_2;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	ಆದರೆ (newsize <= oldsize) {
		ಗಾತ್ರ_t d = oldsize - newsize;

		ಆದರೆ (d < oldsize / 2 && d < (ಗಾತ್ರ_t)getpagesize()) {
			memset((ಅಕ್ಷರ *)ptr + newsize, 0, d);
			ಹಿಂತಿರುಗಿ ptr;
		}
	}

	newptr = ಸ್ಮರಣೆ_ಕೊಡು(newsize);
	ಆದರೆ (newptr == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	ಆದರೆ (newsize > oldsize) {
		ಸ್ಮರಣೆ_ನಕಲು(newptr, ptr, oldsize);
		memset((ಅಕ್ಷರ *)newptr + oldsize, 0, newsize - oldsize);
	} ಇಲ್ಲದಿದ್ದರೆ
		ಸ್ಮರಣೆ_ನಕಲು(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	ಬಿಡುಗಡೆ(ptr);

	ಹಿಂತಿರುಗಿ newptr;
}
/* DEF_WEAK(recallocarray); */

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_RECALLOCARRAY */
