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

#include "includes.h"

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include "bitmap.h"

#define BITMAP_WTYPE	u_int
#define BITMAP_MAX	(1<<24)
#define BITMAP_BYTES	(sizeof(BITMAP_WTYPE))
#define BITMAP_BITS	(sizeof(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
struct bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t top; /* index of top word allocated */
};

struct bitmap *
bitmap_new(void)
{
	struct bitmap *ret;

	nếu ((ret = calloc(1, sizeof(*ret))) == NULL)
		trả_về NULL;
	nếu ((ret->d = calloc(1, BITMAP_BYTES)) == NULL) {
		free(ret);
		trả_về NULL;
	}
	ret->len = 1;
	ret->top = 0;
	trả_về ret;
}

void
bitmap_free(struct bitmap *b)
{
	nếu (b != NULL && b->d != NULL) {
		bitmap_zero(b);
		free(b->d);
		b->d = NULL;
	}
	free(b);
}

void
bitmap_zero(struct bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->top = 0;
}

số_nguyên
bitmap_test_bit(struct bitmap *b, u_int n)
{
	nếu (b->top >= b->len)
		trả_về 0; /* invalid */
	nếu (b->len == 0 || (n / BITMAP_BITS) > b->top)
		trả_về 0;
	trả_về (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

static số_nguyên
reserve(struct bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	nếu (b->top >= b->len || n > BITMAP_MAX)
		trả_về -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	nếu (b->len < nlen) {
		nếu ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == NULL)
			trả_về -1;
		b->d = tmp;
		b->len = nlen;
	}
	trả_về 0;
}

số_nguyên
bitmap_set_bit(struct bitmap *b, u_int n)
{
	số_nguyên r;
	size_t offset;

	nếu ((r = reserve(b, n)) != 0)
		trả_về r;
	offset = n / BITMAP_BITS;
	nếu (offset > b->top)
		b->top = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	trả_về 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
static void
retop(struct bitmap *b)
{
	nếu (b->top >= b->len)
		trả_về;
	trong_khi (b->top > 0 && b->d[b->top] == 0)
		b->top--;
}

void
bitmap_clear_bit(struct bitmap *b, u_int n)
{
	size_t offset;

	nếu (b->top >= b->len || n > BITMAP_MAX)
		trả_về; /* invalid */
	offset = n / BITMAP_BITS;
	nếu (offset > b->top)
		trả_về;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(struct bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	nếu (b->top >= b->len)
		trả_về 0; /* invalid */
	nếu (b->len == 0 || (b->top == 0 && b->d[0] == 0))
		trả_về 0;
	/* Find MSB set */
	w = b->d[b->top];
	bits = (b->top + 1) * BITMAP_BITS;
	trong_khi (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	trả_về bits;
}

size_t
bitmap_nbytes(struct bitmap *b)
{
	trả_về (bitmap_nbits(b) + 7) / 8;
}

số_nguyên
bitmap_to_string(struct bitmap *b, void *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	nếu (l < need || b->top >= b->len)
		trả_về -1;
	nếu (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	cho (i = k = 0; i < b->top + 1; i++) {
		cho (j = 0; j < BITMAP_BYTES; j++) {
			nếu (k >= l)
				break;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	trả_về 0;
}

số_nguyên
bitmap_from_string(struct bitmap *b, const void *p, size_t l)
{
	số_nguyên r;
	size_t i, offset, shift;
	const u_char *s = (const u_char *)p;

	nếu (l > BITMAP_MAX / 8)
		trả_về -1;
	nếu ((r = reserve(b, l * 8)) != 0)
		trả_về r;
	bitmap_zero(b);
	nếu (l == 0)
		trả_về 0;
	b->top = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	cho (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		nếu (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} không_thì
			shift -= 8;
	}
	retop(b);
	trả_về 0;
}
