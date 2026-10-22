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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "bitmap.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BITMAP_WTYPE	u_int
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BITMAP_MAX	(1<<24)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BITMAP_ਬਾਈਟਾਂ	(ਆਕਾਰ(BITMAP_WTYPE))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BITMAP_ਬਿੱਟ	(ਆਕਾਰ(BITMAP_WTYPE) * 8)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_ਬਿੱਟ - 1)
ਬਣਤਰ bitmap {
	BITMAP_WTYPE *d;
	ਮਾਪ_t len; /* number of words allocated */
	ਮਾਪ_t ਸਿਖਰ; /* index of top word allocated */
};

ਬਣਤਰ bitmap *
bitmap_new(ਖਾਲੀ)
{
	ਬਣਤਰ bitmap *ret;

	ਜੇ ((ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ ((ret->d = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, BITMAP_ਬਾਈਟਾਂ)) == ਨਿਰਾ) {
		ਮੁਕਤ(ret);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ret->len = 1;
	ret->ਸਿਖਰ = 0;
	ਵਾਪਸ ret;
}

ਖਾਲੀ
bitmap_free(ਬਣਤਰ bitmap *b)
{
	ਜੇ (b != ਨਿਰਾ && b->d != ਨਿਰਾ) {
		bitmap_zero(b);
		ਮੁਕਤ(b->d);
		b->d = ਨਿਰਾ;
	}
	ਮੁਕਤ(b);
}

ਖਾਲੀ
bitmap_zero(ਬਣਤਰ bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_ਬਾਈਟਾਂ);
	b->ਸਿਖਰ = 0;
}

ਪੂਰਨ
bitmap_test_ਦੋਆਧਾਰੀ_ਅੰਕ(ਬਣਤਰ bitmap *b, u_int n)
{
	ਜੇ (b->ਸਿਖਰ >= b->len)
		ਵਾਪਸ 0; /* invalid */
	ਜੇ (b->len == 0 || (n / BITMAP_ਬਿੱਟ) > b->ਸਿਖਰ)
		ਵਾਪਸ 0;
	ਵਾਪਸ (b->d[n / BITMAP_ਬਿੱਟ] >> (n & BITMAP_WMASK)) & 1;
}

ਸਥਿਰ ਪੂਰਨ
reserve(ਬਣਤਰ bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	ਮਾਪ_t nlen;

	ਜੇ (b->ਸਿਖਰ >= b->len || n > BITMAP_MAX)
		ਵਾਪਸ -1; /* invalid */
	nlen = (n / BITMAP_ਬਿੱਟ) + 1;
	ਜੇ (b->len < nlen) {
		ਜੇ ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_ਬਾਈਟਾਂ)) == ਨਿਰਾ)
			ਵਾਪਸ -1;
		b->d = tmp;
		b->len = nlen;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
bitmap_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(ਬਣਤਰ bitmap *b, u_int n)
{
	ਪੂਰਨ r;
	ਮਾਪ_t ਵਿੱਥ;

	ਜੇ ((r = reserve(b, n)) != 0)
		ਵਾਪਸ r;
	ਵਿੱਥ = n / BITMAP_ਬਿੱਟ;
	ਜੇ (ਵਿੱਥ > b->ਸਿਖਰ)
		b->ਸਿਖਰ = ਵਿੱਥ;
	b->d[ਵਿੱਥ] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	ਵਾਪਸ 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
ਸਥਿਰ ਖਾਲੀ
retop(ਬਣਤਰ bitmap *b)
{
	ਜੇ (b->ਸਿਖਰ >= b->len)
		ਵਾਪਸ;
	ਜਦੋਂ (b->ਸਿਖਰ > 0 && b->d[b->ਸਿਖਰ] == 0)
		b->ਸਿਖਰ--;
}

ਖਾਲੀ
bitmap_clear_ਦੋਆਧਾਰੀ_ਅੰਕ(ਬਣਤਰ bitmap *b, u_int n)
{
	ਮਾਪ_t ਵਿੱਥ;

	ਜੇ (b->ਸਿਖਰ >= b->len || n > BITMAP_MAX)
		ਵਾਪਸ; /* invalid */
	ਵਿੱਥ = n / BITMAP_ਬਿੱਟ;
	ਜੇ (ਵਿੱਥ > b->ਸਿਖਰ)
		ਵਾਪਸ;
	b->d[ਵਿੱਥ] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

ਮਾਪ_t
bitmap_nbits(ਬਣਤਰ bitmap *b)
{
	ਮਾਪ_t ਬਿੱਟ;
	BITMAP_WTYPE w;

	retop(b);
	ਜੇ (b->ਸਿਖਰ >= b->len)
		ਵਾਪਸ 0; /* invalid */
	ਜੇ (b->len == 0 || (b->ਸਿਖਰ == 0 && b->d[0] == 0))
		ਵਾਪਸ 0;
	/* Find MSB set */
	w = b->d[b->ਸਿਖਰ];
	ਬਿੱਟ = (b->ਸਿਖਰ + 1) * BITMAP_ਬਿੱਟ;
	ਜਦੋਂ (!(w & ((BITMAP_WTYPE)1 << (BITMAP_ਬਿੱਟ - 1)))) {
		w <<= 1;
		ਬਿੱਟ--;
	}
	ਵਾਪਸ ਬਿੱਟ;
}

ਮਾਪ_t
bitmap_nbytes(ਬਣਤਰ bitmap *b)
{
	ਵਾਪਸ (bitmap_nbits(b) + 7) / 8;
}

ਪੂਰਨ
bitmap_ਮੰਜ਼ਿਲ_string(ਬਣਤਰ bitmap *b, ਖਾਲੀ *p, ਮਾਪ_t l)
{
	u_char *s = (u_char *)p;
	ਮਾਪ_t i, j, k, need = bitmap_nbytes(b);

	ਜੇ (l < need || b->ਸਿਖਰ >= b->len)
		ਵਾਪਸ -1;
	ਜੇ (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	ਲਈ (i = k = 0; i < b->ਸਿਖਰ + 1; i++) {
		ਲਈ (j = 0; j < BITMAP_ਬਾਈਟਾਂ; j++) {
			ਜੇ (k >= l)
				ਰੋਕੋ;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
bitmap_from_string(ਬਣਤਰ bitmap *b, ਅਚਲ ਖਾਲੀ *p, ਮਾਪ_t l)
{
	ਪੂਰਨ r;
	ਮਾਪ_t i, ਵਿੱਥ, ਖਿਸਕਾਓ;
	ਅਚਲ u_char *s = (ਅਚਲ u_char *)p;

	ਜੇ (l > BITMAP_MAX / 8)
		ਵਾਪਸ -1;
	ਜੇ ((r = reserve(b, l * 8)) != 0)
		ਵਾਪਸ r;
	bitmap_zero(b);
	ਜੇ (l == 0)
		ਵਾਪਸ 0;
	b->ਸਿਖਰ = ਵਿੱਥ = ((l + (BITMAP_ਬਾਈਟਾਂ - 1)) / BITMAP_ਬਾਈਟਾਂ) - 1;
	ਖਿਸਕਾਓ = ((l + (BITMAP_ਬਾਈਟਾਂ - 1)) % BITMAP_ਬਾਈਟਾਂ) * 8;
	ਲਈ (i = 0; i < l; i++) {
		b->d[ਵਿੱਥ] |= (BITMAP_WTYPE)s[i] << ਖਿਸਕਾਓ;
		ਜੇ (ਖਿਸਕਾਓ == 0) {
			ਵਿੱਥ--;
			ਖਿਸਕਾਓ = BITMAP_ਬਿੱਟ - 8;
		} ਨਹੀਂਤਾਂ
			ਖਿਸਕਾਓ -= 8;
	}
	retop(b);
	ਵਾਪਸ 0;
}
