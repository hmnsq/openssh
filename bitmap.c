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

#define BITMAP_WTYPE	u_int
#define BITMAP_MAX	(1<<24)
#define BITMAP_BYTES	(ಪರಿಮಾಣ(BITMAP_WTYPE))
#define BITMAP_BITS	(ಪರಿಮಾಣ(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
ಸಂರಚನಾ bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t ತುದಿ; /* index of top word allocated */
};

ಸಂರಚನಾ bitmap *
bitmap_new(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ bitmap *ret;

	ಯದಿ ((ret = calloc(1, ಪರಿಮಾಣ(*ret))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ ((ret->d = calloc(1, BITMAP_BYTES)) == ರಿಕ್ತ) {
		ಮುಕ್ತ(ret);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ret->len = 1;
	ret->ತುದಿ = 0;
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
bitmap_free(ಸಂರಚನಾ bitmap *b)
{
	ಯದಿ (b != ರಿಕ್ತ && b->d != ರಿಕ್ತ) {
		bitmap_zero(b);
		ಮುಕ್ತ(b->d);
		b->d = ರಿಕ್ತ;
	}
	ಮುಕ್ತ(b);
}

ಶೂನ್ಯ
bitmap_zero(ಸಂರಚನಾ bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->ತುದಿ = 0;
}

ಪೂರ್ಣಾಙ್ಕ
bitmap_test_bit(ಸಂರಚನಾ bitmap *b, u_int n)
{
	ಯದಿ (b->ತುದಿ >= b->len)
		ಪ್ರತ್ಯಾಗಮ 0; /* invalid */
	ಯದಿ (b->len == 0 || (n / BITMAP_BITS) > b->ತುದಿ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
reserve(ಸಂರಚನಾ bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	ಯದಿ (b->ತುದಿ >= b->len || n > BITMAP_MAX)
		ಪ್ರತ್ಯಾಗಮ -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	ಯದಿ (b->len < nlen) {
		ಯದಿ ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ -1;
		b->d = tmp;
		b->len = nlen;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
bitmap_set_bit(ಸಂರಚನಾ bitmap *b, u_int n)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t offset;

	ಯದಿ ((r = reserve(b, n)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	offset = n / BITMAP_BITS;
	ಯದಿ (offset > b->ತುದಿ)
		b->ತುದಿ = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
ಸ್ಥಿರ ಶೂನ್ಯ
retop(ಸಂರಚನಾ bitmap *b)
{
	ಯದಿ (b->ತುದಿ >= b->len)
		ಪ್ರತ್ಯಾಗಮ;
	ಯಾವತ್ (b->ತುದಿ > 0 && b->d[b->ತುದಿ] == 0)
		b->ತುದಿ--;
}

ಶೂನ್ಯ
bitmap_clear_bit(ಸಂರಚನಾ bitmap *b, u_int n)
{
	size_t offset;

	ಯದಿ (b->ತುದಿ >= b->len || n > BITMAP_MAX)
		ಪ್ರತ್ಯಾಗಮ; /* invalid */
	offset = n / BITMAP_BITS;
	ಯದಿ (offset > b->ತುದಿ)
		ಪ್ರತ್ಯಾಗಮ;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(ಸಂರಚನಾ bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	ಯದಿ (b->ತುದಿ >= b->len)
		ಪ್ರತ್ಯಾಗಮ 0; /* invalid */
	ಯದಿ (b->len == 0 || (b->ತುದಿ == 0 && b->d[0] == 0))
		ಪ್ರತ್ಯಾಗಮ 0;
	/* Find MSB set */
	w = b->d[b->ತುದಿ];
	bits = (b->ತುದಿ + 1) * BITMAP_BITS;
	ಯಾವತ್ (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	ಪ್ರತ್ಯಾಗಮ bits;
}

size_t
bitmap_nbytes(ಸಂರಚನಾ bitmap *b)
{
	ಪ್ರತ್ಯಾಗಮ (bitmap_nbits(b) + 7) / 8;
}

ಪೂರ್ಣಾಙ್ಕ
bitmap_to_string(ಸಂರಚನಾ bitmap *b, ಶೂನ್ಯ *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	ಯದಿ (l < need || b->ತುದಿ >= b->len)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	ಪ್ರತಿ (i = k = 0; i < b->ತುದಿ + 1; i++) {
		ಪ್ರತಿ (j = 0; j < BITMAP_BYTES; j++) {
			ಯದಿ (k >= l)
				ಭಙ್ಗ;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
bitmap_from_string(ಸಂರಚನಾ bitmap *b, ಧ್ರುವ ಶೂನ್ಯ *p, size_t l)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t i, offset, shift;
	ಧ್ರುವ u_char *s = (ಧ್ರುವ u_char *)p;

	ಯದಿ (l > BITMAP_MAX / 8)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ ((r = reserve(b, l * 8)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	bitmap_zero(b);
	ಯದಿ (l == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	b->ತುದಿ = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	ಪ್ರತಿ (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		ಯದಿ (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} ಅನ್ಯಥಾ
			shift -= 8;
	}
	retop(b);
	ಪ್ರತ್ಯಾಗಮ 0;
}
