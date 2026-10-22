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

#تعریف_کن BITMAP_WTYPE	u_int
#تعریف_کن BITMAP_MAX	(1<<24)
#تعریف_کن BITMAP_بایتها	(حجم(BITMAP_WTYPE))
#تعریف_کن BITMAP_بیتها	(حجم(BITMAP_WTYPE) * 8)
#تعریف_کن BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_بیتها - 1)
بنية bitmap {
	BITMAP_WTYPE *d;
	اندازه_t len; /* number of words allocated */
	اندازه_t بالاترین; /* index of top word allocated */
};

بنية bitmap *
bitmap_new(فراغ)
{
	بنية bitmap *ret;

	إذا ((ret = حافظه_صفر_بده(1, حجم(*ret))) == عدم)
		أرجع عدم;
	إذا ((ret->d = حافظه_صفر_بده(1, BITMAP_بایتها)) == عدم) {
		حرر(ret);
		أرجع عدم;
	}
	ret->len = 1;
	ret->بالاترین = 0;
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
	memset(b->d, 0, b->len * BITMAP_بایتها);
	b->بالاترین = 0;
}

صحيح
bitmap_test_بیت(بنية bitmap *b, u_int n)
{
	إذا (b->بالاترین >= b->len)
		أرجع 0; /* invalid */
	إذا (b->len == 0 || (n / BITMAP_بیتها) > b->بالاترین)
		أرجع 0;
	أرجع (b->d[n / BITMAP_بیتها] >> (n & BITMAP_WMASK)) & 1;
}

ساكن صحيح
reserve(بنية bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	اندازه_t nlen;

	إذا (b->بالاترین >= b->len || n > BITMAP_MAX)
		أرجع -1; /* invalid */
	nlen = (n / BITMAP_بیتها) + 1;
	إذا (b->len < nlen) {
		إذا ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_بایتها)) == عدم)
			أرجع -1;
		b->d = tmp;
		b->len = nlen;
	}
	أرجع 0;
}

صحيح
bitmap_مجموعه_بیت(بنية bitmap *b, u_int n)
{
	صحيح r;
	اندازه_t جابه_جایی;

	إذا ((r = reserve(b, n)) != 0)
		أرجع r;
	جابه_جایی = n / BITMAP_بیتها;
	إذا (جابه_جایی > b->بالاترین)
		b->بالاترین = جابه_جایی;
	b->d[جابه_جایی] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	أرجع 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
ساكن فراغ
retop(بنية bitmap *b)
{
	إذا (b->بالاترین >= b->len)
		أرجع;
	طالما (b->بالاترین > 0 && b->d[b->بالاترین] == 0)
		b->بالاترین--;
}

فراغ
bitmap_clear_بیت(بنية bitmap *b, u_int n)
{
	اندازه_t جابه_جایی;

	إذا (b->بالاترین >= b->len || n > BITMAP_MAX)
		أرجع; /* invalid */
	جابه_جایی = n / BITMAP_بیتها;
	إذا (جابه_جایی > b->بالاترین)
		أرجع;
	b->d[جابه_جایی] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

اندازه_t
bitmap_nbits(بنية bitmap *b)
{
	اندازه_t بیتها;
	BITMAP_WTYPE w;

	retop(b);
	إذا (b->بالاترین >= b->len)
		أرجع 0; /* invalid */
	إذا (b->len == 0 || (b->بالاترین == 0 && b->d[0] == 0))
		أرجع 0;
	/* Find MSB set */
	w = b->d[b->بالاترین];
	بیتها = (b->بالاترین + 1) * BITMAP_بیتها;
	طالما (!(w & ((BITMAP_WTYPE)1 << (BITMAP_بیتها - 1)))) {
		w <<= 1;
		بیتها--;
	}
	أرجع بیتها;
}

اندازه_t
bitmap_nbytes(بنية bitmap *b)
{
	أرجع (bitmap_nbits(b) + 7) / 8;
}

صحيح
bitmap_مقصد_string(بنية bitmap *b, فراغ *p, اندازه_t l)
{
	u_char *s = (u_char *)p;
	اندازه_t i, j, k, need = bitmap_nbytes(b);

	إذا (l < need || b->بالاترین >= b->len)
		أرجع -1;
	إذا (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	لكل (i = k = 0; i < b->بالاترین + 1; i++) {
		لكل (j = 0; j < BITMAP_بایتها; j++) {
			إذا (k >= l)
				اكسر;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	أرجع 0;
}

صحيح
bitmap_from_string(بنية bitmap *b, ثابت فراغ *p, اندازه_t l)
{
	صحيح r;
	اندازه_t i, جابه_جایی, لغزش;
	ثابت u_char *s = (ثابت u_char *)p;

	إذا (l > BITMAP_MAX / 8)
		أرجع -1;
	إذا ((r = reserve(b, l * 8)) != 0)
		أرجع r;
	bitmap_zero(b);
	إذا (l == 0)
		أرجع 0;
	b->بالاترین = جابه_جایی = ((l + (BITMAP_بایتها - 1)) / BITMAP_بایتها) - 1;
	لغزش = ((l + (BITMAP_بایتها - 1)) % BITMAP_بایتها) * 8;
	لكل (i = 0; i < l; i++) {
		b->d[جابه_جایی] |= (BITMAP_WTYPE)s[i] << لغزش;
		إذا (لغزش == 0) {
			جابه_جایی--;
			لغزش = BITMAP_بیتها - 8;
		} وإلا
			لغزش -= 8;
	}
	retop(b);
	أرجع 0;
}
