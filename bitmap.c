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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <string.h>
#ضمن <stdlib.h>

#ضمن "bitmap.h"

#define BITMAP_WTYPE	u_int
#define BITMAP_MAX	(1<<24)
#define BITMAP_BYTES	(حجم(BITMAP_WTYPE))
#define BITMAP_BITS	(حجم(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
بنية bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t چوققا; /* index of top word allocated */
};

بنية bitmap *
bitmap_new(فراغ)
{
	بنية bitmap *ret;

	إذا ((ret = calloc(1, حجم(*ret))) == عدم)
		أرجع عدم;
	إذا ((ret->d = calloc(1, BITMAP_BYTES)) == عدم) {
		حرر(ret);
		أرجع عدم;
	}
	ret->len = 1;
	ret->چوققا = 0;
	أرجع ret;
}

فراغ
bitmap_free(بنية bitmap *b)
{
	إذا (b != عدم && b->d != عدم) {
		bitmap_zero(b);
		حرر(b->d);
		b->d = عدم;
	}
	حرر(b);
}

فراغ
bitmap_zero(بنية bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->چوققا = 0;
}

صحيح
bitmap_test_bit(بنية bitmap *b, u_int n)
{
	إذا (b->چوققا >= b->len)
		أرجع 0; /* invalid */
	إذا (b->len == 0 || (n / BITMAP_BITS) > b->چوققا)
		أرجع 0;
	أرجع (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

ساكن صحيح
reserve(بنية bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	إذا (b->چوققا >= b->len || n > BITMAP_MAX)
		أرجع -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	إذا (b->len < nlen) {
		إذا ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == عدم)
			أرجع -1;
		b->d = tmp;
		b->len = nlen;
	}
	أرجع 0;
}

صحيح
bitmap_set_bit(بنية bitmap *b, u_int n)
{
	صحيح r;
	size_t offset;

	إذا ((r = reserve(b, n)) != 0)
		أرجع r;
	offset = n / BITMAP_BITS;
	إذا (offset > b->چوققا)
		b->چوققا = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	أرجع 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
ساكن فراغ
retop(بنية bitmap *b)
{
	إذا (b->چوققا >= b->len)
		أرجع;
	طالما (b->چوققا > 0 && b->d[b->چوققا] == 0)
		b->چوققا--;
}

فراغ
bitmap_clear_bit(بنية bitmap *b, u_int n)
{
	size_t offset;

	إذا (b->چوققا >= b->len || n > BITMAP_MAX)
		أرجع; /* invalid */
	offset = n / BITMAP_BITS;
	إذا (offset > b->چوققا)
		أرجع;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(بنية bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	إذا (b->چوققا >= b->len)
		أرجع 0; /* invalid */
	إذا (b->len == 0 || (b->چوققا == 0 && b->d[0] == 0))
		أرجع 0;
	/* Find MSB set */
	w = b->d[b->چوققا];
	bits = (b->چوققا + 1) * BITMAP_BITS;
	طالما (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	أرجع bits;
}

size_t
bitmap_nbytes(بنية bitmap *b)
{
	أرجع (bitmap_nbits(b) + 7) / 8;
}

صحيح
bitmap_to_string(بنية bitmap *b, فراغ *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	إذا (l < need || b->چوققا >= b->len)
		أرجع -1;
	إذا (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	لكل (i = k = 0; i < b->چوققا + 1; i++) {
		لكل (j = 0; j < BITMAP_BYTES; j++) {
			إذا (k >= l)
				اكسر;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	أرجع 0;
}

صحيح
bitmap_from_string(بنية bitmap *b, ثابت فراغ *p, size_t l)
{
	صحيح r;
	size_t i, offset, shift;
	ثابت u_char *s = (ثابت u_char *)p;

	إذا (l > BITMAP_MAX / 8)
		أرجع -1;
	إذا ((r = reserve(b, l * 8)) != 0)
		أرجع r;
	bitmap_zero(b);
	إذا (l == 0)
		أرجع 0;
	b->چوققا = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	لكل (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		إذا (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} وإلا
			shift -= 8;
	}
	retop(b);
	أرجع 0;
}
