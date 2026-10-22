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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <string.h>
#شامل <stdlib.h>

#شامل "bitmap.h"

#define BITMAP_WTYPE	u_int
#define BITMAP_MAX	(1<<24)
#define BITMAP_BYTES	(اندازه(BITMAP_WTYPE))
#define BITMAP_BITS	(اندازه(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
ساختار bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t بالاترین; /* index of top word allocated */
};

ساختار bitmap *
bitmap_new(تهی)
{
	ساختار bitmap *ret;

	اگر ((ret = calloc(1, اندازه(*ret))) == پوچ)
		بازگشت پوچ;
	اگر ((ret->d = calloc(1, BITMAP_BYTES)) == پوچ) {
		آزاد(ret);
		بازگشت پوچ;
	}
	ret->len = 1;
	ret->بالاترین = 0;
	بازگشت ret;
}

تهی
bitmap_free(ساختار bitmap *b)
{
	اگر (b != پوچ && b->d != پوچ) {
		bitmap_zero(b);
		آزاد(b->d);
		b->d = پوچ;
	}
	آزاد(b);
}

تهی
bitmap_zero(ساختار bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->بالاترین = 0;
}

صحیح
bitmap_test_bit(ساختار bitmap *b, u_int n)
{
	اگر (b->بالاترین >= b->len)
		بازگشت 0; /* invalid */
	اگر (b->len == 0 || (n / BITMAP_BITS) > b->بالاترین)
		بازگشت 0;
	بازگشت (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

ایستا صحیح
reserve(ساختار bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	اگر (b->بالاترین >= b->len || n > BITMAP_MAX)
		بازگشت -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	اگر (b->len < nlen) {
		اگر ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == پوچ)
			بازگشت -1;
		b->d = tmp;
		b->len = nlen;
	}
	بازگشت 0;
}

صحیح
bitmap_set_bit(ساختار bitmap *b, u_int n)
{
	صحیح r;
	size_t offset;

	اگر ((r = reserve(b, n)) != 0)
		بازگشت r;
	offset = n / BITMAP_BITS;
	اگر (offset > b->بالاترین)
		b->بالاترین = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	بازگشت 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
ایستا تهی
retop(ساختار bitmap *b)
{
	اگر (b->بالاترین >= b->len)
		بازگشت;
	وقتی (b->بالاترین > 0 && b->d[b->بالاترین] == 0)
		b->بالاترین--;
}

تهی
bitmap_clear_bit(ساختار bitmap *b, u_int n)
{
	size_t offset;

	اگر (b->بالاترین >= b->len || n > BITMAP_MAX)
		بازگشت; /* invalid */
	offset = n / BITMAP_BITS;
	اگر (offset > b->بالاترین)
		بازگشت;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(ساختار bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	اگر (b->بالاترین >= b->len)
		بازگشت 0; /* invalid */
	اگر (b->len == 0 || (b->بالاترین == 0 && b->d[0] == 0))
		بازگشت 0;
	/* Find MSB set */
	w = b->d[b->بالاترین];
	bits = (b->بالاترین + 1) * BITMAP_BITS;
	وقتی (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	بازگشت bits;
}

size_t
bitmap_nbytes(ساختار bitmap *b)
{
	بازگشت (bitmap_nbits(b) + 7) / 8;
}

صحیح
bitmap_to_string(ساختار bitmap *b, تهی *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	اگر (l < need || b->بالاترین >= b->len)
		بازگشت -1;
	اگر (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	برای (i = k = 0; i < b->بالاترین + 1; i++) {
		برای (j = 0; j < BITMAP_BYTES; j++) {
			اگر (k >= l)
				بشکن;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	بازگشت 0;
}

صحیح
bitmap_from_string(ساختار bitmap *b, ثابت تهی *p, size_t l)
{
	صحیح r;
	size_t i, offset, shift;
	ثابت u_char *s = (ثابت u_char *)p;

	اگر (l > BITMAP_MAX / 8)
		بازگشت -1;
	اگر ((r = reserve(b, l * 8)) != 0)
		بازگشت r;
	bitmap_zero(b);
	اگر (l == 0)
		بازگشت 0;
	b->بالاترین = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	برای (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		اگر (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} وگرنه
			shift -= 8;
	}
	retop(b);
	بازگشت 0;
}
