/* $OpenBSD: bitmap.c,v 1.9 2017/10/20 01:56:39 djm Exp $ */
/*
 * Copyright (c) 2015 Damien Miller <djm@mindrot.org>
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಅನ್ತರ್ಭಾವ "bitmap.h"

#ವ್ಯಾಖ್ಯಾನಿಸು BITMAP_WTYPE	u_int
#ವ್ಯಾಖ್ಯಾನಿಸು BITMAP_MAX	(1<<24)
#ವ್ಯಾಖ್ಯಾನಿಸು BITMAP_ಬೈಟುಗಳು	(ಗಾತ್ರ(BITMAP_WTYPE))
#ವ್ಯಾಖ್ಯಾನಿಸು BITMAP_ಬಿಟ್ಟುಗಳು	(ಗಾತ್ರ(BITMAP_WTYPE) * 8)
#ವ್ಯಾಖ್ಯಾನಿಸು BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_ಬಿಟ್ಟುಗಳು - 1)
ರಚನೆ bitmap {
	BITMAP_WTYPE *d;
	ಗಾತ್ರ_t len; /* number of words allocated */
	ಗಾತ್ರ_t ತುದಿ; /* index of top word allocated */
};

ರಚನೆ bitmap *
bitmap_new(ಶೂನ್ಯ)
{
	ರಚನೆ bitmap *ret;

	ಆದರೆ ((ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ ((ret->d = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, BITMAP_ಬೈಟುಗಳು)) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(ret);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ret->len = 1;
	ret->ತುದಿ = 0;
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
bitmap_free(ರಚನೆ bitmap *b)
{
	ಆದರೆ (b != ಖಾಲಿ && b->d != ಖಾಲಿ) {
		bitmap_zero(b);
		ಬಿಡುಗಡೆ(b->d);
		b->d = ಖಾಲಿ;
	}
	ಬಿಡುಗಡೆ(b);
}

ಶೂನ್ಯ
bitmap_zero(ರಚನೆ bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_ಬೈಟುಗಳು);
	b->ತುದಿ = 0;
}

ಪೂರ್ಣಾಂಕ
bitmap_test_ಬಿಟ್(ರಚನೆ bitmap *b, u_int n)
{
	ಆದರೆ (b->ತುದಿ >= b->len)
		ಹಿಂತಿರುಗಿ 0; /* invalid */
	ಆದರೆ (b->len == 0 || (n / BITMAP_ಬಿಟ್ಟುಗಳು) > b->ತುದಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ (b->d[n / BITMAP_ಬಿಟ್ಟುಗಳು] >> (n & BITMAP_WMASK)) & 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
reserve(ರಚನೆ bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	ಗಾತ್ರ_t nlen;

	ಆದರೆ (b->ತುದಿ >= b->len || n > BITMAP_MAX)
		ಹಿಂತಿರುಗಿ -1; /* invalid */
	nlen = (n / BITMAP_ಬಿಟ್ಟುಗಳು) + 1;
	ಆದರೆ (b->len < nlen) {
		ಆದರೆ ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_ಬೈಟುಗಳು)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ -1;
		b->d = tmp;
		b->len = nlen;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
bitmap_ಗಣ_ಬಿಟ್(ರಚನೆ bitmap *b, u_int n)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ;

	ಆದರೆ ((r = reserve(b, n)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಸ್ಥಾನಾಂತರ = n / BITMAP_ಬಿಟ್ಟುಗಳು;
	ಆದರೆ (ಸ್ಥಾನಾಂತರ > b->ತುದಿ)
		b->ತುದಿ = ಸ್ಥಾನಾಂತರ;
	b->d[ಸ್ಥಾನಾಂತರ] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	ಹಿಂತಿರುಗಿ 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
ಸ್ಥಿರ ಶೂನ್ಯ
retop(ರಚನೆ bitmap *b)
{
	ಆದರೆ (b->ತುದಿ >= b->len)
		ಹಿಂತಿರುಗಿ;
	ಆಗ (b->ತುದಿ > 0 && b->d[b->ತುದಿ] == 0)
		b->ತುದಿ--;
}

ಶೂನ್ಯ
bitmap_clear_ಬಿಟ್(ರಚನೆ bitmap *b, u_int n)
{
	ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ;

	ಆದರೆ (b->ತುದಿ >= b->len || n > BITMAP_MAX)
		ಹಿಂತಿರುಗಿ; /* invalid */
	ಸ್ಥಾನಾಂತರ = n / BITMAP_ಬಿಟ್ಟುಗಳು;
	ಆದರೆ (ಸ್ಥಾನಾಂತರ > b->ತುದಿ)
		ಹಿಂತಿರುಗಿ;
	b->d[ಸ್ಥಾನಾಂತರ] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

ಗಾತ್ರ_t
bitmap_nbits(ರಚನೆ bitmap *b)
{
	ಗಾತ್ರ_t ಬಿಟ್ಟುಗಳು;
	BITMAP_WTYPE w;

	retop(b);
	ಆದರೆ (b->ತುದಿ >= b->len)
		ಹಿಂತಿರುಗಿ 0; /* invalid */
	ಆದರೆ (b->len == 0 || (b->ತುದಿ == 0 && b->d[0] == 0))
		ಹಿಂತಿರುಗಿ 0;
	/* Find MSB set */
	w = b->d[b->ತುದಿ];
	ಬಿಟ್ಟುಗಳು = (b->ತುದಿ + 1) * BITMAP_ಬಿಟ್ಟುಗಳು;
	ಆಗ (!(w & ((BITMAP_WTYPE)1 << (BITMAP_ಬಿಟ್ಟುಗಳು - 1)))) {
		w <<= 1;
		ಬಿಟ್ಟುಗಳು--;
	}
	ಹಿಂತಿರುಗಿ ಬಿಟ್ಟುಗಳು;
}

ಗಾತ್ರ_t
bitmap_nbytes(ರಚನೆ bitmap *b)
{
	ಹಿಂತಿರುಗಿ (bitmap_nbits(b) + 7) / 8;
}

ಪೂರ್ಣಾಂಕ
bitmap_ಗಮ್ಯ_string(ರಚನೆ bitmap *b, ಶೂನ್ಯ *p, ಗಾತ್ರ_t l)
{
	u_char *s = (u_char *)p;
	ಗಾತ್ರ_t i, j, k, need = bitmap_nbytes(b);

	ಆದರೆ (l < need || b->ತುದಿ >= b->len)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	ಗಾಗಿ (i = k = 0; i < b->ತುದಿ + 1; i++) {
		ಗಾಗಿ (j = 0; j < BITMAP_ಬೈಟುಗಳು; j++) {
			ಆದರೆ (k >= l)
				ನಿಲ್ಲಿಸು;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
bitmap_from_string(ರಚನೆ bitmap *b, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *p, ಗಾತ್ರ_t l)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t i, ಸ್ಥಾನಾಂತರ, ಸರಿಸು;
	ಸ್ಥಿರಾಂಕ u_char *s = (ಸ್ಥಿರಾಂಕ u_char *)p;

	ಆದರೆ (l > BITMAP_MAX / 8)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ ((r = reserve(b, l * 8)) != 0)
		ಹಿಂತಿರುಗಿ r;
	bitmap_zero(b);
	ಆದರೆ (l == 0)
		ಹಿಂತಿರುಗಿ 0;
	b->ತುದಿ = ಸ್ಥಾನಾಂತರ = ((l + (BITMAP_ಬೈಟುಗಳು - 1)) / BITMAP_ಬೈಟುಗಳು) - 1;
	ಸರಿಸು = ((l + (BITMAP_ಬೈಟುಗಳು - 1)) % BITMAP_ಬೈಟುಗಳು) * 8;
	ಗಾಗಿ (i = 0; i < l; i++) {
		b->d[ಸ್ಥಾನಾಂತರ] |= (BITMAP_WTYPE)s[i] << ಸರಿಸು;
		ಆದರೆ (ಸರಿಸು == 0) {
			ಸ್ಥಾನಾಂತರ--;
			ಸರಿಸು = BITMAP_ಬಿಟ್ಟುಗಳು - 8;
		} ಇಲ್ಲದಿದ್ದರೆ
			ಸರಿಸು -= 8;
	}
	retop(b);
	ಹಿಂತಿರುಗಿ 0;
}
