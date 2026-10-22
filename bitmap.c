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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>

#અન્તર્ભાવ "bitmap.h"

#define BITMAP_WTYPE	u_int
#define BITMAP_MAX	(1<<24)
#define BITMAP_BYTES	(કદ(BITMAP_WTYPE))
#define BITMAP_BITS	(કદ(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
સંરચના bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t ટોચ; /* index of top word allocated */
};

સંરચના bitmap *
bitmap_new(શૂન્ય)
{
	સંરચના bitmap *ret;

	જો ((ret = calloc(1, કદ(*ret))) == ખાલી)
		પાછા ખાલી;
	જો ((ret->d = calloc(1, BITMAP_BYTES)) == ખાલી) {
		મુક્ત(ret);
		પાછા ખાલી;
	}
	ret->len = 1;
	ret->ટોચ = 0;
	પાછા ret;
}

શૂન્ય
bitmap_free(સંરચના bitmap *b)
{
	જો (b != ખાલી && b->d != ખાલી) {
		bitmap_zero(b);
		મુક્ત(b->d);
		b->d = ખાલી;
	}
	મુક્ત(b);
}

શૂન્ય
bitmap_zero(સંરચના bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->ટોચ = 0;
}

પૂર્ણાંક
bitmap_test_bit(સંરચના bitmap *b, u_int n)
{
	જો (b->ટોચ >= b->len)
		પાછા 0; /* invalid */
	જો (b->len == 0 || (n / BITMAP_BITS) > b->ટોચ)
		પાછા 0;
	પાછા (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

સ્થિર પૂર્ણાંક
reserve(સંરચના bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	જો (b->ટોચ >= b->len || n > BITMAP_MAX)
		પાછા -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	જો (b->len < nlen) {
		જો ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == ખાલી)
			પાછા -1;
		b->d = tmp;
		b->len = nlen;
	}
	પાછા 0;
}

પૂર્ણાંક
bitmap_set_bit(સંરચના bitmap *b, u_int n)
{
	પૂર્ણાંક r;
	size_t offset;

	જો ((r = reserve(b, n)) != 0)
		પાછા r;
	offset = n / BITMAP_BITS;
	જો (offset > b->ટોચ)
		b->ટોચ = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	પાછા 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
સ્થિર શૂન્ય
retop(સંરચના bitmap *b)
{
	જો (b->ટોચ >= b->len)
		પાછા;
	જ્યારે (b->ટોચ > 0 && b->d[b->ટોચ] == 0)
		b->ટોચ--;
}

શૂન્ય
bitmap_clear_bit(સંરચના bitmap *b, u_int n)
{
	size_t offset;

	જો (b->ટોચ >= b->len || n > BITMAP_MAX)
		પાછા; /* invalid */
	offset = n / BITMAP_BITS;
	જો (offset > b->ટોચ)
		પાછા;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(સંરચના bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	જો (b->ટોચ >= b->len)
		પાછા 0; /* invalid */
	જો (b->len == 0 || (b->ટોચ == 0 && b->d[0] == 0))
		પાછા 0;
	/* Find MSB set */
	w = b->d[b->ટોચ];
	bits = (b->ટોચ + 1) * BITMAP_BITS;
	જ્યારે (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	પાછા bits;
}

size_t
bitmap_nbytes(સંરચના bitmap *b)
{
	પાછા (bitmap_nbits(b) + 7) / 8;
}

પૂર્ણાંક
bitmap_to_string(સંરચના bitmap *b, શૂન્ય *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	જો (l < need || b->ટોચ >= b->len)
		પાછા -1;
	જો (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	માટે (i = k = 0; i < b->ટોચ + 1; i++) {
		માટે (j = 0; j < BITMAP_BYTES; j++) {
			જો (k >= l)
				તોડો;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	પાછા 0;
}

પૂર્ણાંક
bitmap_from_string(સંરચના bitmap *b, અચલ શૂન્ય *p, size_t l)
{
	પૂર્ણાંક r;
	size_t i, offset, shift;
	અચલ u_char *s = (અચલ u_char *)p;

	જો (l > BITMAP_MAX / 8)
		પાછા -1;
	જો ((r = reserve(b, l * 8)) != 0)
		પાછા r;
	bitmap_zero(b);
	જો (l == 0)
		પાછા 0;
	b->ટોચ = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	માટે (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		જો (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} નહીંતર
			shift -= 8;
	}
	retop(b);
	પાછા 0;
}
