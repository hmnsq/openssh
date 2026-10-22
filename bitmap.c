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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>

#অন্তর্ভাব "bitmap.h"

#define BITMAP_WTYPE	u_int
#define BITMAP_MAX	(1<<24)
#define BITMAP_BYTES	(আকার(BITMAP_WTYPE))
#define BITMAP_BITS	(আকার(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
কাঠামো bitmap {
	BITMAP_WTYPE *d;
	আকার_t len; /* number of words allocated */
	আকার_t শীর্ষ; /* index of top word allocated */
};

কাঠামো bitmap *
bitmap_new(শূন্য)
{
	কাঠামো bitmap *ret;

	যদি ((ret = calloc(1, আকার(*ret))) == ফাঁকা)
		ফেরত ফাঁকা;
	যদি ((ret->d = calloc(1, BITMAP_BYTES)) == ফাঁকা) {
		মুক্ত(ret);
		ফেরত ফাঁকা;
	}
	ret->len = 1;
	ret->শীর্ষ = 0;
	ফেরত ret;
}

শূন্য
bitmap_free(কাঠামো bitmap *b)
{
	যদি (b != ফাঁকা && b->d != ফাঁকা) {
		bitmap_zero(b);
		মুক্ত(b->d);
		b->d = ফাঁকা;
	}
	মুক্ত(b);
}

শূন্য
bitmap_zero(কাঠামো bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->শীর্ষ = 0;
}

পূর্ণসংখ্যা
bitmap_test_bit(কাঠামো bitmap *b, u_int n)
{
	যদি (b->শীর্ষ >= b->len)
		ফেরত 0; /* invalid */
	যদি (b->len == 0 || (n / BITMAP_BITS) > b->শীর্ষ)
		ফেরত 0;
	ফেরত (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

স্থির পূর্ণসংখ্যা
reserve(কাঠামো bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	আকার_t nlen;

	যদি (b->শীর্ষ >= b->len || n > BITMAP_MAX)
		ফেরত -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	যদি (b->len < nlen) {
		যদি ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == ফাঁকা)
			ফেরত -1;
		b->d = tmp;
		b->len = nlen;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
bitmap_set_bit(কাঠামো bitmap *b, u_int n)
{
	পূর্ণসংখ্যা r;
	আকার_t offset;

	যদি ((r = reserve(b, n)) != 0)
		ফেরত r;
	offset = n / BITMAP_BITS;
	যদি (offset > b->শীর্ষ)
		b->শীর্ষ = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	ফেরত 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
স্থির শূন্য
retop(কাঠামো bitmap *b)
{
	যদি (b->শীর্ষ >= b->len)
		ফেরত;
	যখন (b->শীর্ষ > 0 && b->d[b->শীর্ষ] == 0)
		b->শীর্ষ--;
}

শূন্য
bitmap_clear_bit(কাঠামো bitmap *b, u_int n)
{
	আকার_t offset;

	যদি (b->শীর্ষ >= b->len || n > BITMAP_MAX)
		ফেরত; /* invalid */
	offset = n / BITMAP_BITS;
	যদি (offset > b->শীর্ষ)
		ফেরত;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

আকার_t
bitmap_nbits(কাঠামো bitmap *b)
{
	আকার_t bits;
	BITMAP_WTYPE w;

	retop(b);
	যদি (b->শীর্ষ >= b->len)
		ফেরত 0; /* invalid */
	যদি (b->len == 0 || (b->শীর্ষ == 0 && b->d[0] == 0))
		ফেরত 0;
	/* Find MSB set */
	w = b->d[b->শীর্ষ];
	bits = (b->শীর্ষ + 1) * BITMAP_BITS;
	যখন (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	ফেরত bits;
}

আকার_t
bitmap_nbytes(কাঠামো bitmap *b)
{
	ফেরত (bitmap_nbits(b) + 7) / 8;
}

পূর্ণসংখ্যা
bitmap_to_string(কাঠামো bitmap *b, শূন্য *p, আকার_t l)
{
	u_char *s = (u_char *)p;
	আকার_t i, j, k, need = bitmap_nbytes(b);

	যদি (l < need || b->শীর্ষ >= b->len)
		ফেরত -1;
	যদি (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	জন্য (i = k = 0; i < b->শীর্ষ + 1; i++) {
		জন্য (j = 0; j < BITMAP_BYTES; j++) {
			যদি (k >= l)
				বিরতি;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
bitmap_from_string(কাঠামো bitmap *b, ধ্রুবক শূন্য *p, আকার_t l)
{
	পূর্ণসংখ্যা r;
	আকার_t i, offset, shift;
	ধ্রুবক u_char *s = (ধ্রুবক u_char *)p;

	যদি (l > BITMAP_MAX / 8)
		ফেরত -1;
	যদি ((r = reserve(b, l * 8)) != 0)
		ফেরত r;
	bitmap_zero(b);
	যদি (l == 0)
		ফেরত 0;
	b->শীর্ষ = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	জন্য (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		যদি (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} অন্যথা
			shift -= 8;
	}
	retop(b);
	ফেরত 0;
}
