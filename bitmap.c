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

	如果 ((ret = calloc(1, sizeof(*ret))) == NULL)
		返回 NULL;
	如果 ((ret->d = calloc(1, BITMAP_BYTES)) == NULL) {
		free(ret);
		返回 NULL;
	}
	ret->len = 1;
	ret->top = 0;
	返回 ret;
}

void
bitmap_free(struct bitmap *b)
{
	如果 (b != NULL && b->d != NULL) {
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

整数
bitmap_test_bit(struct bitmap *b, u_int n)
{
	如果 (b->top >= b->len)
		返回 0; /* invalid */
	如果 (b->len == 0 || (n / BITMAP_BITS) > b->top)
		返回 0;
	返回 (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

static 整数
reserve(struct bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	如果 (b->top >= b->len || n > BITMAP_MAX)
		返回 -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	如果 (b->len < nlen) {
		如果 ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == NULL)
			返回 -1;
		b->d = tmp;
		b->len = nlen;
	}
	返回 0;
}

整数
bitmap_set_bit(struct bitmap *b, u_int n)
{
	整数 r;
	size_t offset;

	如果 ((r = reserve(b, n)) != 0)
		返回 r;
	offset = n / BITMAP_BITS;
	如果 (offset > b->top)
		b->top = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	返回 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
static void
retop(struct bitmap *b)
{
	如果 (b->top >= b->len)
		返回;
	当 (b->top > 0 && b->d[b->top] == 0)
		b->top--;
}

void
bitmap_clear_bit(struct bitmap *b, u_int n)
{
	size_t offset;

	如果 (b->top >= b->len || n > BITMAP_MAX)
		返回; /* invalid */
	offset = n / BITMAP_BITS;
	如果 (offset > b->top)
		返回;
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
	如果 (b->top >= b->len)
		返回 0; /* invalid */
	如果 (b->len == 0 || (b->top == 0 && b->d[0] == 0))
		返回 0;
	/* Find MSB set */
	w = b->d[b->top];
	bits = (b->top + 1) * BITMAP_BITS;
	当 (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	返回 bits;
}

size_t
bitmap_nbytes(struct bitmap *b)
{
	返回 (bitmap_nbits(b) + 7) / 8;
}

整数
bitmap_to_string(struct bitmap *b, void *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	如果 (l < need || b->top >= b->len)
		返回 -1;
	如果 (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	为 (i = k = 0; i < b->top + 1; i++) {
		为 (j = 0; j < BITMAP_BYTES; j++) {
			如果 (k >= l)
				break;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	返回 0;
}

整数
bitmap_from_string(struct bitmap *b, const void *p, size_t l)
{
	整数 r;
	size_t i, offset, shift;
	const u_char *s = (const u_char *)p;

	如果 (l > BITMAP_MAX / 8)
		返回 -1;
	如果 ((r = reserve(b, l * 8)) != 0)
		返回 r;
	bitmap_zero(b);
	如果 (l == 0)
		返回 0;
	b->top = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	为 (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		如果 (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} 否则
			shift -= 8;
	}
	retop(b);
	返回 0;
}
