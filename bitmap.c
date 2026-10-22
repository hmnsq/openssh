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
#define BITMAP_BYTES	(পরিমাণ(BITMAP_WTYPE))
#define BITMAP_BITS	(পরিমাণ(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
সংরচনা bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t শীর্ষ; /* index of top word allocated */
};

সংরচনা bitmap *
bitmap_new(শূন্য)
{
	সংরচনা bitmap *ret;

	যদি ((ret = calloc(1, পরিমাণ(*ret))) == রিক্ত)
		প্রত্যাগম রিক্ত;
	যদি ((ret->d = calloc(1, BITMAP_BYTES)) == রিক্ত) {
		মুক্ত(ret);
		প্রত্যাগম রিক্ত;
	}
	ret->len = 1;
	ret->শীর্ষ = 0;
	প্রত্যাগম ret;
}

শূন্য
bitmap_free(সংরচনা bitmap *b)
{
	যদি (b != রিক্ত && b->d != রিক্ত) {
		bitmap_zero(b);
		মুক্ত(b->d);
		b->d = রিক্ত;
	}
	মুক্ত(b);
}

শূন্য
bitmap_zero(সংরচনা bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->শীর্ষ = 0;
}

পূর্ণাঙ্ক
bitmap_test_bit(সংরচনা bitmap *b, u_int n)
{
	যদি (b->শীর্ষ >= b->len)
		প্রত্যাগম 0; /* invalid */
	যদি (b->len == 0 || (n / BITMAP_BITS) > b->শীর্ষ)
		প্রত্যাগম 0;
	প্রত্যাগম (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

স্থির পূর্ণাঙ্ক
reserve(সংরচনা bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	যদি (b->শীর্ষ >= b->len || n > BITMAP_MAX)
		প্রত্যাগম -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	যদি (b->len < nlen) {
		যদি ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == রিক্ত)
			প্রত্যাগম -1;
		b->d = tmp;
		b->len = nlen;
	}
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
bitmap_set_bit(সংরচনা bitmap *b, u_int n)
{
	পূর্ণাঙ্ক r;
	size_t offset;

	যদি ((r = reserve(b, n)) != 0)
		প্রত্যাগম r;
	offset = n / BITMAP_BITS;
	যদি (offset > b->শীর্ষ)
		b->শীর্ষ = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	প্রত্যাগম 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
স্থির শূন্য
retop(সংরচনা bitmap *b)
{
	যদি (b->শীর্ষ >= b->len)
		প্রত্যাগম;
	যাবত্ (b->শীর্ষ > 0 && b->d[b->শীর্ষ] == 0)
		b->শীর্ষ--;
}

শূন্য
bitmap_clear_bit(সংরচনা bitmap *b, u_int n)
{
	size_t offset;

	যদি (b->শীর্ষ >= b->len || n > BITMAP_MAX)
		প্রত্যাগম; /* invalid */
	offset = n / BITMAP_BITS;
	যদি (offset > b->শীর্ষ)
		প্রত্যাগম;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(সংরচনা bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	যদি (b->শীর্ষ >= b->len)
		প্রত্যাগম 0; /* invalid */
	যদি (b->len == 0 || (b->শীর্ষ == 0 && b->d[0] == 0))
		প্রত্যাগম 0;
	/* Find MSB set */
	w = b->d[b->শীর্ষ];
	bits = (b->শীর্ষ + 1) * BITMAP_BITS;
	যাবত্ (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	প্রত্যাগম bits;
}

size_t
bitmap_nbytes(সংরচনা bitmap *b)
{
	প্রত্যাগম (bitmap_nbits(b) + 7) / 8;
}

পূর্ণাঙ্ক
bitmap_to_string(সংরচনা bitmap *b, শূন্য *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	যদি (l < need || b->শীর্ষ >= b->len)
		প্রত্যাগম -1;
	যদি (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	প্রতি (i = k = 0; i < b->শীর্ষ + 1; i++) {
		প্রতি (j = 0; j < BITMAP_BYTES; j++) {
			যদি (k >= l)
				ভঙ্গ;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
bitmap_from_string(সংরচনা bitmap *b, ধ্রুব শূন্য *p, size_t l)
{
	পূর্ণাঙ্ক r;
	size_t i, offset, shift;
	ধ্রুব u_char *s = (ধ্রুব u_char *)p;

	যদি (l > BITMAP_MAX / 8)
		প্রত্যাগম -1;
	যদি ((r = reserve(b, l * 8)) != 0)
		প্রত্যাগম r;
	bitmap_zero(b);
	যদি (l == 0)
		প্রত্যাগম 0;
	b->শীর্ষ = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	প্রতি (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		যদি (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} অন্যথা
			shift -= 8;
	}
	retop(b);
	প্রত্যাগম 0;
}
