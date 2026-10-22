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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>

#അന്തര്ഭാവ "bitmap.h"

#define BITMAP_WTYPE	u_int
#define BITMAP_MAX	(1<<24)
#define BITMAP_BYTES	(വലുപ്പം(BITMAP_WTYPE))
#define BITMAP_BITS	(വലുപ്പം(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
ഘടന bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t മുകൾ; /* index of top word allocated */
};

ഘടന bitmap *
bitmap_new(ശൂന്യം)
{
	ഘടന bitmap *ret;

	എങ്കിൽ ((ret = calloc(1, വലുപ്പം(*ret))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	എങ്കിൽ ((ret->d = calloc(1, BITMAP_BYTES)) == ശൂന്യ) {
		സ്വതന്ത്രം(ret);
		തിരികെ ശൂന്യ;
	}
	ret->len = 1;
	ret->മുകൾ = 0;
	തിരികെ ret;
}

ശൂന്യം
bitmap_free(ഘടന bitmap *b)
{
	എങ്കിൽ (b != ശൂന്യ && b->d != ശൂന്യ) {
		bitmap_zero(b);
		സ്വതന്ത്രം(b->d);
		b->d = ശൂന്യ;
	}
	സ്വതന്ത്രം(b);
}

ശൂന്യം
bitmap_zero(ഘടന bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->മുകൾ = 0;
}

പൂർണ്ണസംഖ്യ
bitmap_test_bit(ഘടന bitmap *b, u_int n)
{
	എങ്കിൽ (b->മുകൾ >= b->len)
		തിരികെ 0; /* invalid */
	എങ്കിൽ (b->len == 0 || (n / BITMAP_BITS) > b->മുകൾ)
		തിരികെ 0;
	തിരികെ (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
reserve(ഘടന bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	എങ്കിൽ (b->മുകൾ >= b->len || n > BITMAP_MAX)
		തിരികെ -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	എങ്കിൽ (b->len < nlen) {
		എങ്കിൽ ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == ശൂന്യ)
			തിരികെ -1;
		b->d = tmp;
		b->len = nlen;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
bitmap_set_bit(ഘടന bitmap *b, u_int n)
{
	പൂർണ്ണസംഖ്യ r;
	size_t offset;

	എങ്കിൽ ((r = reserve(b, n)) != 0)
		തിരികെ r;
	offset = n / BITMAP_BITS;
	എങ്കിൽ (offset > b->മുകൾ)
		b->മുകൾ = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	തിരികെ 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
സ്ഥിതം ശൂന്യം
retop(ഘടന bitmap *b)
{
	എങ്കിൽ (b->മുകൾ >= b->len)
		തിരികെ;
	ആകുമ്പോൾ (b->മുകൾ > 0 && b->d[b->മുകൾ] == 0)
		b->മുകൾ--;
}

ശൂന്യം
bitmap_clear_bit(ഘടന bitmap *b, u_int n)
{
	size_t offset;

	എങ്കിൽ (b->മുകൾ >= b->len || n > BITMAP_MAX)
		തിരികെ; /* invalid */
	offset = n / BITMAP_BITS;
	എങ്കിൽ (offset > b->മുകൾ)
		തിരികെ;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(ഘടന bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	എങ്കിൽ (b->മുകൾ >= b->len)
		തിരികെ 0; /* invalid */
	എങ്കിൽ (b->len == 0 || (b->മുകൾ == 0 && b->d[0] == 0))
		തിരികെ 0;
	/* Find MSB set */
	w = b->d[b->മുകൾ];
	bits = (b->മുകൾ + 1) * BITMAP_BITS;
	ആകുമ്പോൾ (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	തിരികെ bits;
}

size_t
bitmap_nbytes(ഘടന bitmap *b)
{
	തിരികെ (bitmap_nbits(b) + 7) / 8;
}

പൂർണ്ണസംഖ്യ
bitmap_to_string(ഘടന bitmap *b, ശൂന്യം *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	എങ്കിൽ (l < need || b->മുകൾ >= b->len)
		തിരികെ -1;
	എങ്കിൽ (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	വേണ്ടി (i = k = 0; i < b->മുകൾ + 1; i++) {
		വേണ്ടി (j = 0; j < BITMAP_BYTES; j++) {
			എങ്കിൽ (k >= l)
				നിർത്തുക;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
bitmap_from_string(ഘടന bitmap *b, സ്ഥിരം ശൂന്യം *p, size_t l)
{
	പൂർണ്ണസംഖ്യ r;
	size_t i, offset, shift;
	സ്ഥിരം u_char *s = (സ്ഥിരം u_char *)p;

	എങ്കിൽ (l > BITMAP_MAX / 8)
		തിരികെ -1;
	എങ്കിൽ ((r = reserve(b, l * 8)) != 0)
		തിരികെ r;
	bitmap_zero(b);
	എങ്കിൽ (l == 0)
		തിരികെ 0;
	b->മുകൾ = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	വേണ്ടി (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		എങ്കിൽ (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} അല്ലെങ്കിൽ
			shift -= 8;
	}
	retop(b);
	തിരികെ 0;
}
