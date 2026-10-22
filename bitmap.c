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
#define BITMAP_BYTES	(parimaa_na(BITMAP_WTYPE))
#define BITMAP_BITS	(parimaa_na(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
sa_nracanaa bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t top; /* index of top word allocated */
};

sa_nracanaa bitmap *
bitmap_new(void)
{
	sa_nracanaa bitmap *ret;

	ᬬᬾᬦ᭄ ((ret = calloc(1, parimaa_na(*ret))) == NULL)
		ᬯᬮᬶ NULL;
	ᬬᬾᬦ᭄ ((ret->d = calloc(1, BITMAP_BYTES)) == NULL) {
		free(ret);
		ᬯᬮᬶ NULL;
	}
	ret->len = 1;
	ret->top = 0;
	ᬯᬮᬶ ret;
}

void
bitmap_free(sa_nracanaa bitmap *b)
{
	ᬬᬾᬦ᭄ (b != NULL && b->d != NULL) {
		bitmap_zero(b);
		free(b->d);
		b->d = NULL;
	}
	free(b);
}

void
bitmap_zero(sa_nracanaa bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->top = 0;
}

puur_naa_nka
bitmap_test_bit(sa_nracanaa bitmap *b, u_int n)
{
	ᬬᬾᬦ᭄ (b->top >= b->len)
		ᬯᬮᬶ 0; /* invalid */
	ᬬᬾᬦ᭄ (b->len == 0 || (n / BITMAP_BITS) > b->top)
		ᬯᬮᬶ 0;
	ᬯᬮᬶ (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

static puur_naa_nka
reserve(sa_nracanaa bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	ᬬᬾᬦ᭄ (b->top >= b->len || n > BITMAP_MAX)
		ᬯᬮᬶ -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	ᬬᬾᬦ᭄ (b->len < nlen) {
		ᬬᬾᬦ᭄ ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == NULL)
			ᬯᬮᬶ -1;
		b->d = tmp;
		b->len = nlen;
	}
	ᬯᬮᬶ 0;
}

puur_naa_nka
bitmap_set_bit(sa_nracanaa bitmap *b, u_int n)
{
	puur_naa_nka r;
	size_t offset;

	ᬬᬾᬦ᭄ ((r = reserve(b, n)) != 0)
		ᬯᬮᬶ r;
	offset = n / BITMAP_BITS;
	ᬬᬾᬦ᭄ (offset > b->top)
		b->top = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	ᬯᬮᬶ 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
static void
retop(sa_nracanaa bitmap *b)
{
	ᬬᬾᬦ᭄ (b->top >= b->len)
		ᬯᬮᬶ;
	ᬲᭂᬤᭂᬮ (b->top > 0 && b->d[b->top] == 0)
		b->top--;
}

void
bitmap_clear_bit(sa_nracanaa bitmap *b, u_int n)
{
	size_t offset;

	ᬬᬾᬦ᭄ (b->top >= b->len || n > BITMAP_MAX)
		ᬯᬮᬶ; /* invalid */
	offset = n / BITMAP_BITS;
	ᬬᬾᬦ᭄ (offset > b->top)
		ᬯᬮᬶ;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(sa_nracanaa bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	ᬬᬾᬦ᭄ (b->top >= b->len)
		ᬯᬮᬶ 0; /* invalid */
	ᬬᬾᬦ᭄ (b->len == 0 || (b->top == 0 && b->d[0] == 0))
		ᬯᬮᬶ 0;
	/* Find MSB set */
	w = b->d[b->top];
	bits = (b->top + 1) * BITMAP_BITS;
	ᬲᭂᬤᭂᬮ (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	ᬯᬮᬶ bits;
}

size_t
bitmap_nbytes(sa_nracanaa bitmap *b)
{
	ᬯᬮᬶ (bitmap_nbits(b) + 7) / 8;
}

puur_naa_nka
bitmap_to_string(sa_nracanaa bitmap *b, void *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	ᬬᬾᬦ᭄ (l < need || b->top >= b->len)
		ᬯᬮᬶ -1;
	ᬬᬾᬦ᭄ (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	for (i = k = 0; i < b->top + 1; i++) {
		for (j = 0; j < BITMAP_BYTES; j++) {
			ᬬᬾᬦ᭄ (k >= l)
				bha_nga;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	ᬯᬮᬶ 0;
}

puur_naa_nka
bitmap_from_string(sa_nracanaa bitmap *b, const void *p, size_t l)
{
	puur_naa_nka r;
	size_t i, offset, shift;
	const u_char *s = (const u_char *)p;

	ᬬᬾᬦ᭄ (l > BITMAP_MAX / 8)
		ᬯᬮᬶ -1;
	ᬬᬾᬦ᭄ ((r = reserve(b, l * 8)) != 0)
		ᬯᬮᬶ r;
	bitmap_zero(b);
	ᬬᬾᬦ᭄ (l == 0)
		ᬯᬮᬶ 0;
	b->top = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	for (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		ᬬᬾᬦ᭄ (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} ᬮᬶᬬ
			shift -= 8;
	}
	retop(b);
	ᬯᬮᬶ 0;
}
