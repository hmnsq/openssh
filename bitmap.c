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

#تعریف_کرو BITMAP_WTYPE	u_int
#تعریف_کرو BITMAP_MAX	(1<<24)
#تعریف_کرو BITMAP_بائٹیں	(حجم(BITMAP_WTYPE))
#تعریف_کرو BITMAP_بٹ	(حجم(BITMAP_WTYPE) * 8)
#تعریف_کرو BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_بٹ - 1)
ساخت bitmap {
	BITMAP_WTYPE *d;
	سائز_t len; /* number of words allocated */
	سائز_t چوٹی; /* index of top word allocated */
};

ساخت bitmap *
bitmap_new(خالی)
{
	ساخت bitmap *ret;

	اگر ((ret = صفر_حافظہ_دو(1, حجم(*ret))) == تہی)
		واپس تہی;
	اگر ((ret->d = صفر_حافظہ_دو(1, BITMAP_بائٹیں)) == تہی) {
		آزاد(ret);
		واپس تہی;
	}
	ret->len = 1;
	ret->چوٹی = 0;
	واپس ret;
}

خالی
bitmap_free(ساخت bitmap *b)
{
	اگر (b != تہی && b->d != تہی) {
		bitmap_zero(b);
		آزاد(b->d);
		b->d = تہی;
	}
	آزاد(b);
}

خالی
bitmap_zero(ساخت bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_بائٹیں);
	b->چوٹی = 0;
}

صحیح
bitmap_test_ثنائی_ہندسہ(ساخت bitmap *b, u_int n)
{
	اگر (b->چوٹی >= b->len)
		واپس 0; /* invalid */
	اگر (b->len == 0 || (n / BITMAP_بٹ) > b->چوٹی)
		واپس 0;
	واپس (b->d[n / BITMAP_بٹ] >> (n & BITMAP_WMASK)) & 1;
}

ساکن صحیح
reserve(ساخت bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	سائز_t nlen;

	اگر (b->چوٹی >= b->len || n > BITMAP_MAX)
		واپس -1; /* invalid */
	nlen = (n / BITMAP_بٹ) + 1;
	اگر (b->len < nlen) {
		اگر ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_بائٹیں)) == تہی)
			واپس -1;
		b->d = tmp;
		b->len = nlen;
	}
	واپس 0;
}

صحیح
bitmap_سیٹ_ثنائی_ہندسہ(ساخت bitmap *b, u_int n)
{
	صحیح r;
	سائز_t انحراف;

	اگر ((r = reserve(b, n)) != 0)
		واپس r;
	انحراف = n / BITMAP_بٹ;
	اگر (انحراف > b->چوٹی)
		b->چوٹی = انحراف;
	b->d[انحراف] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	واپس 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
ساکن خالی
retop(ساخت bitmap *b)
{
	اگر (b->چوٹی >= b->len)
		واپس;
	جب (b->چوٹی > 0 && b->d[b->چوٹی] == 0)
		b->چوٹی--;
}

خالی
bitmap_clear_ثنائی_ہندسہ(ساخت bitmap *b, u_int n)
{
	سائز_t انحراف;

	اگر (b->چوٹی >= b->len || n > BITMAP_MAX)
		واپس; /* invalid */
	انحراف = n / BITMAP_بٹ;
	اگر (انحراف > b->چوٹی)
		واپس;
	b->d[انحراف] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

سائز_t
bitmap_nbits(ساخت bitmap *b)
{
	سائز_t بٹ;
	BITMAP_WTYPE w;

	retop(b);
	اگر (b->چوٹی >= b->len)
		واپس 0; /* invalid */
	اگر (b->len == 0 || (b->چوٹی == 0 && b->d[0] == 0))
		واپس 0;
	/* Find MSB set */
	w = b->d[b->چوٹی];
	بٹ = (b->چوٹی + 1) * BITMAP_بٹ;
	جب (!(w & ((BITMAP_WTYPE)1 << (BITMAP_بٹ - 1)))) {
		w <<= 1;
		بٹ--;
	}
	واپس بٹ;
}

سائز_t
bitmap_nbytes(ساخت bitmap *b)
{
	واپس (bitmap_nbits(b) + 7) / 8;
}

صحیح
bitmap_مقصد_string(ساخت bitmap *b, خالی *p, سائز_t l)
{
	u_char *s = (u_char *)p;
	سائز_t i, j, k, need = bitmap_nbytes(b);

	اگر (l < need || b->چوٹی >= b->len)
		واپس -1;
	اگر (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	برائے (i = k = 0; i < b->چوٹی + 1; i++) {
		برائے (j = 0; j < BITMAP_بائٹیں; j++) {
			اگر (k >= l)
				توڑو;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	واپس 0;
}

صحیح
bitmap_from_string(ساخت bitmap *b, ثابت خالی *p, سائز_t l)
{
	صحیح r;
	سائز_t i, انحراف, سرکاؤ;
	ثابت u_char *s = (ثابت u_char *)p;

	اگر (l > BITMAP_MAX / 8)
		واپس -1;
	اگر ((r = reserve(b, l * 8)) != 0)
		واپس r;
	bitmap_zero(b);
	اگر (l == 0)
		واپس 0;
	b->چوٹی = انحراف = ((l + (BITMAP_بائٹیں - 1)) / BITMAP_بائٹیں) - 1;
	سرکاؤ = ((l + (BITMAP_بائٹیں - 1)) % BITMAP_بائٹیں) * 8;
	برائے (i = 0; i < l; i++) {
		b->d[انحراف] |= (BITMAP_WTYPE)s[i] << سرکاؤ;
		اگر (سرکاؤ == 0) {
			انحراف--;
			سرکاؤ = BITMAP_بٹ - 8;
		} ورنہ
			سرکاؤ -= 8;
	}
	retop(b);
	واپس 0;
}
