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

#تعریف_کرو BITMAP_WTYPE	u_int
#تعریف_کرو BITMAP_MAX	(1<<24)
#تعریف_کرو BITMAP_بائٹاں	(حجم(BITMAP_WTYPE))
#تعریف_کرو BITMAP_بٹ	(حجم(BITMAP_WTYPE) * 8)
#تعریف_کرو BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_بٹ - 1)
بنية bitmap {
	BITMAP_WTYPE *d;
	ناپ_t len; /* number of words allocated */
	ناپ_t چوٹی; /* index of top word allocated */
};

بنية bitmap *
bitmap_new(فراغ)
{
	بنية bitmap *ret;

	إذا ((ret = صفر_حافظہ_دیو(1, حجم(*ret))) == عدم)
		أرجع عدم;
	إذا ((ret->d = صفر_حافظہ_دیو(1, BITMAP_بائٹاں)) == عدم) {
		حرر(ret);
		أرجع عدم;
	}
	ret->len = 1;
	ret->چوٹی = 0;
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
	memset(b->d, 0, b->len * BITMAP_بائٹاں);
	b->چوٹی = 0;
}

صحيح
bitmap_test_ثنائی_ہندسہ(بنية bitmap *b, u_int n)
{
	إذا (b->چوٹی >= b->len)
		أرجع 0; /* invalid */
	إذا (b->len == 0 || (n / BITMAP_بٹ) > b->چوٹی)
		أرجع 0;
	أرجع (b->d[n / BITMAP_بٹ] >> (n & BITMAP_WMASK)) & 1;
}

ساكن صحيح
reserve(بنية bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	ناپ_t nlen;

	إذا (b->چوٹی >= b->len || n > BITMAP_MAX)
		أرجع -1; /* invalid */
	nlen = (n / BITMAP_بٹ) + 1;
	إذا (b->len < nlen) {
		إذا ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_بائٹاں)) == عدم)
			أرجع -1;
		b->d = tmp;
		b->len = nlen;
	}
	أرجع 0;
}

صحيح
bitmap_سیٹ_ثنائی_ہندسہ(بنية bitmap *b, u_int n)
{
	صحيح r;
	ناپ_t وتھ;

	إذا ((r = reserve(b, n)) != 0)
		أرجع r;
	وتھ = n / BITMAP_بٹ;
	إذا (وتھ > b->چوٹی)
		b->چوٹی = وتھ;
	b->d[وتھ] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	أرجع 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
ساكن فراغ
retop(بنية bitmap *b)
{
	إذا (b->چوٹی >= b->len)
		أرجع;
	طالما (b->چوٹی > 0 && b->d[b->چوٹی] == 0)
		b->چوٹی--;
}

فراغ
bitmap_clear_ثنائی_ہندسہ(بنية bitmap *b, u_int n)
{
	ناپ_t وتھ;

	إذا (b->چوٹی >= b->len || n > BITMAP_MAX)
		أرجع; /* invalid */
	وتھ = n / BITMAP_بٹ;
	إذا (وتھ > b->چوٹی)
		أرجع;
	b->d[وتھ] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

ناپ_t
bitmap_nbits(بنية bitmap *b)
{
	ناپ_t بٹ;
	BITMAP_WTYPE w;

	retop(b);
	إذا (b->چوٹی >= b->len)
		أرجع 0; /* invalid */
	إذا (b->len == 0 || (b->چوٹی == 0 && b->d[0] == 0))
		أرجع 0;
	/* Find MSB set */
	w = b->d[b->چوٹی];
	بٹ = (b->چوٹی + 1) * BITMAP_بٹ;
	طالما (!(w & ((BITMAP_WTYPE)1 << (BITMAP_بٹ - 1)))) {
		w <<= 1;
		بٹ--;
	}
	أرجع بٹ;
}

ناپ_t
bitmap_nbytes(بنية bitmap *b)
{
	أرجع (bitmap_nbits(b) + 7) / 8;
}

صحيح
bitmap_منزل_string(بنية bitmap *b, فراغ *p, ناپ_t l)
{
	u_char *s = (u_char *)p;
	ناپ_t i, j, k, need = bitmap_nbytes(b);

	إذا (l < need || b->چوٹی >= b->len)
		أرجع -1;
	إذا (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	لكل (i = k = 0; i < b->چوٹی + 1; i++) {
		لكل (j = 0; j < BITMAP_بائٹاں; j++) {
			إذا (k >= l)
				اكسر;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	أرجع 0;
}

صحيح
bitmap_from_string(بنية bitmap *b, ثابت فراغ *p, ناپ_t l)
{
	صحيح r;
	ناپ_t i, وتھ, کھسکاؤ;
	ثابت u_char *s = (ثابت u_char *)p;

	إذا (l > BITMAP_MAX / 8)
		أرجع -1;
	إذا ((r = reserve(b, l * 8)) != 0)
		أرجع r;
	bitmap_zero(b);
	إذا (l == 0)
		أرجع 0;
	b->چوٹی = وتھ = ((l + (BITMAP_بائٹاں - 1)) / BITMAP_بائٹاں) - 1;
	کھسکاؤ = ((l + (BITMAP_بائٹاں - 1)) % BITMAP_بائٹاں) * 8;
	لكل (i = 0; i < l; i++) {
		b->d[وتھ] |= (BITMAP_WTYPE)s[i] << کھسکاؤ;
		إذا (کھسکاؤ == 0) {
			وتھ--;
			کھسکاؤ = BITMAP_بٹ - 8;
		} وإلا
			کھسکاؤ -= 8;
	}
	retop(b);
	أرجع 0;
}
