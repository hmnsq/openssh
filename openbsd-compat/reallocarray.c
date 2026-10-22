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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_REALLOCARRAY

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#ವ್ಯಾಖ್ಯಾನಿಸು MUL_NO_ಅತಿಪ್ರವಾಹ	((ಗಾತ್ರ_t)1 << (ಗಾತ್ರ(ಗಾತ್ರ_t) * 4))

ಶೂನ್ಯ *
reallocarray(ಶೂನ್ಯ *optr, ಗಾತ್ರ_t nmemb, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ ((nmemb >= MUL_NO_ಅತಿಪ್ರವಾಹ || ಗಾತ್ರ_2 >= MUL_NO_ಅತಿಪ್ರವಾಹ) &&
	    nmemb > 0 && SIZE_MAX / nmemb < ಗಾತ್ರ_2) {
		errno = ENOMEM;
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ realloc(optr, ಗಾತ್ರ_2 * nmemb);
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_REALLOCARRAY */
