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

#وصف_ڪريو BITMAP_WTYPE	u_int
#وصف_ڪريو BITMAP_MAX	(1<<24)
#وصف_ڪريو BITMAP_بائيٽون	(حجم(BITMAP_WTYPE))
#وصف_ڪريو BITMAP_بٽ	(حجم(BITMAP_WTYPE) * 8)
#وصف_ڪريو BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_بٽ - 1)
بنية bitmap {
	BITMAP_WTYPE *d;
	سائيز_t len; /* number of words allocated */
	سائيز_t چوٽي; /* index of top word allocated */
};

بنية bitmap *
bitmap_new(فراغ)
{
	بنية bitmap *ret;

	إذا ((ret = صفر_يادگيري_ڏيو(1, حجم(*ret))) == عدم)
		أرجع عدم;
	إذا ((ret->d = صفر_يادگيري_ڏيو(1, BITMAP_بائيٽون)) == عدم) {
		حرر(ret);
		أرجع عدم;
	}
	ret->len = 1;
	ret->چوٽي = 0;
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
	memset(b->d, 0, b->len * BITMAP_بائيٽون);
	b->چوٽي = 0;
}

صحيح
bitmap_test_ٻٽو_انگ(بنية bitmap *b, u_int n)
{
	إذا (b->چوٽي >= b->len)
		أرجع 0; /* invalid */
	إذا (b->len == 0 || (n / BITMAP_بٽ) > b->چوٽي)
		أرجع 0;
	أرجع (b->d[n / BITMAP_بٽ] >> (n & BITMAP_WMASK)) & 1;
}

ساكن صحيح
reserve(بنية bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	سائيز_t nlen;

	إذا (b->چوٽي >= b->len || n > BITMAP_MAX)
		أرجع -1; /* invalid */
	nlen = (n / BITMAP_بٽ) + 1;
	إذا (b->len < nlen) {
		إذا ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_بائيٽون)) == عدم)
			أرجع -1;
		b->d = tmp;
		b->len = nlen;
	}
	أرجع 0;
}

صحيح
bitmap_سيٽ_ٻٽو_انگ(بنية bitmap *b, u_int n)
{
	صحيح r;
	سائيز_t وٿي;

	إذا ((r = reserve(b, n)) != 0)
		أرجع r;
	وٿي = n / BITMAP_بٽ;
	إذا (وٿي > b->چوٽي)
		b->چوٽي = وٿي;
	b->d[وٿي] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	أرجع 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
ساكن فراغ
retop(بنية bitmap *b)
{
	إذا (b->چوٽي >= b->len)
		أرجع;
	طالما (b->چوٽي > 0 && b->d[b->چوٽي] == 0)
		b->چوٽي--;
}

فراغ
bitmap_clear_ٻٽو_انگ(بنية bitmap *b, u_int n)
{
	سائيز_t وٿي;

	إذا (b->چوٽي >= b->len || n > BITMAP_MAX)
		أرجع; /* invalid */
	وٿي = n / BITMAP_بٽ;
	إذا (وٿي > b->چوٽي)
		أرجع;
	b->d[وٿي] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

سائيز_t
bitmap_nbits(بنية bitmap *b)
{
	سائيز_t بٽ;
	BITMAP_WTYPE w;

	retop(b);
	إذا (b->چوٽي >= b->len)
		أرجع 0; /* invalid */
	إذا (b->len == 0 || (b->چوٽي == 0 && b->d[0] == 0))
		أرجع 0;
	/* Find MSB set */
	w = b->d[b->چوٽي];
	بٽ = (b->چوٽي + 1) * BITMAP_بٽ;
	طالما (!(w & ((BITMAP_WTYPE)1 << (BITMAP_بٽ - 1)))) {
		w <<= 1;
		بٽ--;
	}
	أرجع بٽ;
}

سائيز_t
bitmap_nbytes(بنية bitmap *b)
{
	أرجع (bitmap_nbits(b) + 7) / 8;
}

صحيح
bitmap_منزل_string(بنية bitmap *b, فراغ *p, سائيز_t l)
{
	u_char *s = (u_char *)p;
	سائيز_t i, j, k, need = bitmap_nbytes(b);

	إذا (l < need || b->چوٽي >= b->len)
		أرجع -1;
	إذا (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	لكل (i = k = 0; i < b->چوٽي + 1; i++) {
		لكل (j = 0; j < BITMAP_بائيٽون; j++) {
			إذا (k >= l)
				اكسر;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	أرجع 0;
}

صحيح
bitmap_from_string(بنية bitmap *b, ثابت فراغ *p, سائيز_t l)
{
	صحيح r;
	سائيز_t i, وٿي, سرڪايو;
	ثابت u_char *s = (ثابت u_char *)p;

	إذا (l > BITMAP_MAX / 8)
		أرجع -1;
	إذا ((r = reserve(b, l * 8)) != 0)
		أرجع r;
	bitmap_zero(b);
	إذا (l == 0)
		أرجع 0;
	b->چوٽي = وٿي = ((l + (BITMAP_بائيٽون - 1)) / BITMAP_بائيٽون) - 1;
	سرڪايو = ((l + (BITMAP_بائيٽون - 1)) % BITMAP_بائيٽون) * 8;
	لكل (i = 0; i < l; i++) {
		b->d[وٿي] |= (BITMAP_WTYPE)s[i] << سرڪايو;
		إذا (سرڪايو == 0) {
			وٿي--;
			سرڪايو = BITMAP_بٽ - 8;
		} وإلا
			سرڪايو -= 8;
	}
	retop(b);
	أرجع 0;
}
