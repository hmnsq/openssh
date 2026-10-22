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

	ប្រសិនបើ ((ret = calloc(1, parimaa_na(*ret))) == NULL)
		ត្រឡប់ NULL;
	ប្រសិនបើ ((ret->d = calloc(1, BITMAP_BYTES)) == NULL) {
		free(ret);
		ត្រឡប់ NULL;
	}
	ret->len = 1;
	ret->top = 0;
	ត្រឡប់ ret;
}

void
bitmap_free(sa_nracanaa bitmap *b)
{
	ប្រសិនបើ (b != NULL && b->d != NULL) {
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

ចំនួនគត់
bitmap_test_bit(sa_nracanaa bitmap *b, u_int n)
{
	ប្រសិនបើ (b->top >= b->len)
		ត្រឡប់ 0; /* invalid */
	ប្រសិនបើ (b->len == 0 || (n / BITMAP_BITS) > b->top)
		ត្រឡប់ 0;
	ត្រឡប់ (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

static ចំនួនគត់
reserve(sa_nracanaa bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	ប្រសិនបើ (b->top >= b->len || n > BITMAP_MAX)
		ត្រឡប់ -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	ប្រសិនបើ (b->len < nlen) {
		ប្រសិនបើ ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == NULL)
			ត្រឡប់ -1;
		b->d = tmp;
		b->len = nlen;
	}
	ត្រឡប់ 0;
}

ចំនួនគត់
bitmap_set_bit(sa_nracanaa bitmap *b, u_int n)
{
	ចំនួនគត់ r;
	size_t offset;

	ប្រសិនបើ ((r = reserve(b, n)) != 0)
		ត្រឡប់ r;
	offset = n / BITMAP_BITS;
	ប្រសិនបើ (offset > b->top)
		b->top = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	ត្រឡប់ 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
static void
retop(sa_nracanaa bitmap *b)
{
	ប្រសិនបើ (b->top >= b->len)
		ត្រឡប់;
	ខណៈពេល (b->top > 0 && b->d[b->top] == 0)
		b->top--;
}

void
bitmap_clear_bit(sa_nracanaa bitmap *b, u_int n)
{
	size_t offset;

	ប្រសិនបើ (b->top >= b->len || n > BITMAP_MAX)
		ត្រឡប់; /* invalid */
	offset = n / BITMAP_BITS;
	ប្រសិនបើ (offset > b->top)
		ត្រឡប់;
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
	ប្រសិនបើ (b->top >= b->len)
		ត្រឡប់ 0; /* invalid */
	ប្រសិនបើ (b->len == 0 || (b->top == 0 && b->d[0] == 0))
		ត្រឡប់ 0;
	/* Find MSB set */
	w = b->d[b->top];
	bits = (b->top + 1) * BITMAP_BITS;
	ខណៈពេល (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	ត្រឡប់ bits;
}

size_t
bitmap_nbytes(sa_nracanaa bitmap *b)
{
	ត្រឡប់ (bitmap_nbits(b) + 7) / 8;
}

ចំនួនគត់
bitmap_to_string(sa_nracanaa bitmap *b, void *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	ប្រសិនបើ (l < need || b->top >= b->len)
		ត្រឡប់ -1;
	ប្រសិនបើ (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	សម្រាប់ (i = k = 0; i < b->top + 1; i++) {
		សម្រាប់ (j = 0; j < BITMAP_BYTES; j++) {
			ប្រសិនបើ (k >= l)
				bha_nga;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	ត្រឡប់ 0;
}

ចំនួនគត់
bitmap_from_string(sa_nracanaa bitmap *b, const void *p, size_t l)
{
	ចំនួនគត់ r;
	size_t i, offset, shift;
	const u_char *s = (const u_char *)p;

	ប្រសិនបើ (l > BITMAP_MAX / 8)
		ត្រឡប់ -1;
	ប្រសិនបើ ((r = reserve(b, l * 8)) != 0)
		ត្រឡប់ r;
	bitmap_zero(b);
	ប្រសិនបើ (l == 0)
		ត្រឡប់ 0;
	b->top = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	សម្រាប់ (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		ប្រសិនបើ (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} បើមិនដូច្នេះ
			shift -= 8;
	}
	retop(b);
	ត្រឡប់ 0;
}
