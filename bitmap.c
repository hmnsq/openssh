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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>

#அந்தர்பாவ "bitmap.h"

#define BITMAP_WTYPE	u_int
#define BITMAP_MAX	(1<<24)
#define BITMAP_BYTES	(அளவு(BITMAP_WTYPE))
#define BITMAP_BITS	(அளவு(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
கட்டமைப்பு bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t உச்சி; /* index of top word allocated */
};

கட்டமைப்பு bitmap *
bitmap_new(வெறுமை)
{
	கட்டமைப்பு bitmap *ret;

	எனில் ((ret = calloc(1, அளவு(*ret))) == வெற்று)
		திரும்பு வெற்று;
	எனில் ((ret->d = calloc(1, BITMAP_BYTES)) == வெற்று) {
		விடுவி(ret);
		திரும்பு வெற்று;
	}
	ret->len = 1;
	ret->உச்சி = 0;
	திரும்பு ret;
}

வெறுமை
bitmap_free(கட்டமைப்பு bitmap *b)
{
	எனில் (b != வெற்று && b->d != வெற்று) {
		bitmap_zero(b);
		விடுவி(b->d);
		b->d = வெற்று;
	}
	விடுவி(b);
}

வெறுமை
bitmap_zero(கட்டமைப்பு bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->உச்சி = 0;
}

முழு
bitmap_test_bit(கட்டமைப்பு bitmap *b, u_int n)
{
	எனில் (b->உச்சி >= b->len)
		திரும்பு 0; /* invalid */
	எனில் (b->len == 0 || (n / BITMAP_BITS) > b->உச்சி)
		திரும்பு 0;
	திரும்பு (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

நிலையான முழு
reserve(கட்டமைப்பு bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	எனில் (b->உச்சி >= b->len || n > BITMAP_MAX)
		திரும்பு -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	எனில் (b->len < nlen) {
		எனில் ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == வெற்று)
			திரும்பு -1;
		b->d = tmp;
		b->len = nlen;
	}
	திரும்பு 0;
}

முழு
bitmap_set_bit(கட்டமைப்பு bitmap *b, u_int n)
{
	முழு r;
	size_t offset;

	எனில் ((r = reserve(b, n)) != 0)
		திரும்பு r;
	offset = n / BITMAP_BITS;
	எனில் (offset > b->உச்சி)
		b->உச்சி = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	திரும்பு 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
நிலையான வெறுமை
retop(கட்டமைப்பு bitmap *b)
{
	எனில் (b->உச்சி >= b->len)
		திரும்பு;
	போது (b->உச்சி > 0 && b->d[b->உச்சி] == 0)
		b->உச்சி--;
}

வெறுமை
bitmap_clear_bit(கட்டமைப்பு bitmap *b, u_int n)
{
	size_t offset;

	எனில் (b->உச்சி >= b->len || n > BITMAP_MAX)
		திரும்பு; /* invalid */
	offset = n / BITMAP_BITS;
	எனில் (offset > b->உச்சி)
		திரும்பு;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(கட்டமைப்பு bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	எனில் (b->உச்சி >= b->len)
		திரும்பு 0; /* invalid */
	எனில் (b->len == 0 || (b->உச்சி == 0 && b->d[0] == 0))
		திரும்பு 0;
	/* Find MSB set */
	w = b->d[b->உச்சி];
	bits = (b->உச்சி + 1) * BITMAP_BITS;
	போது (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	திரும்பு bits;
}

size_t
bitmap_nbytes(கட்டமைப்பு bitmap *b)
{
	திரும்பு (bitmap_nbits(b) + 7) / 8;
}

முழு
bitmap_to_string(கட்டமைப்பு bitmap *b, வெறுமை *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	எனில் (l < need || b->உச்சி >= b->len)
		திரும்பு -1;
	எனில் (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	க்கு (i = k = 0; i < b->உச்சி + 1; i++) {
		க்கு (j = 0; j < BITMAP_BYTES; j++) {
			எனில் (k >= l)
				நிறுத்து;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	திரும்பு 0;
}

முழு
bitmap_from_string(கட்டமைப்பு bitmap *b, மாறிலி வெறுமை *p, size_t l)
{
	முழு r;
	size_t i, offset, shift;
	மாறிலி u_char *s = (மாறிலி u_char *)p;

	எனில் (l > BITMAP_MAX / 8)
		திரும்பு -1;
	எனில் ((r = reserve(b, l * 8)) != 0)
		திரும்பு r;
	bitmap_zero(b);
	எனில் (l == 0)
		திரும்பு 0;
	b->உச்சி = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	க்கு (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		எனில் (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} இல்லையெனில்
			shift -= 8;
	}
	retop(b);
	திரும்பு 0;
}
