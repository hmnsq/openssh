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

	အကယ်၍ ((ret = calloc(1, parimaa_na(*ret))) == NULL)
		ပြန်ပေး NULL;
	အကယ်၍ ((ret->d = calloc(1, BITMAP_BYTES)) == NULL) {
		free(ret);
		ပြန်ပေး NULL;
	}
	ret->len = 1;
	ret->top = 0;
	ပြန်ပေး ret;
}

void
bitmap_free(sa_nracanaa bitmap *b)
{
	အကယ်၍ (b != NULL && b->d != NULL) {
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

ကိန်းပြည့်
bitmap_test_bit(sa_nracanaa bitmap *b, u_int n)
{
	အကယ်၍ (b->top >= b->len)
		ပြန်ပေး 0; /* invalid */
	အကယ်၍ (b->len == 0 || (n / BITMAP_BITS) > b->top)
		ပြန်ပေး 0;
	ပြန်ပေး (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

static ကိန်းပြည့်
reserve(sa_nracanaa bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	အကယ်၍ (b->top >= b->len || n > BITMAP_MAX)
		ပြန်ပေး -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	အကယ်၍ (b->len < nlen) {
		အကယ်၍ ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == NULL)
			ပြန်ပေး -1;
		b->d = tmp;
		b->len = nlen;
	}
	ပြန်ပေး 0;
}

ကိန်းပြည့်
bitmap_set_bit(sa_nracanaa bitmap *b, u_int n)
{
	ကိန်းပြည့် r;
	size_t offset;

	အကယ်၍ ((r = reserve(b, n)) != 0)
		ပြန်ပေး r;
	offset = n / BITMAP_BITS;
	အကယ်၍ (offset > b->top)
		b->top = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	ပြန်ပေး 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
static void
retop(sa_nracanaa bitmap *b)
{
	အကယ်၍ (b->top >= b->len)
		ပြန်ပေး;
	နေစဉ် (b->top > 0 && b->d[b->top] == 0)
		b->top--;
}

void
bitmap_clear_bit(sa_nracanaa bitmap *b, u_int n)
{
	size_t offset;

	အကယ်၍ (b->top >= b->len || n > BITMAP_MAX)
		ပြန်ပေး; /* invalid */
	offset = n / BITMAP_BITS;
	အကယ်၍ (offset > b->top)
		ပြန်ပေး;
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
	အကယ်၍ (b->top >= b->len)
		ပြန်ပေး 0; /* invalid */
	အကယ်၍ (b->len == 0 || (b->top == 0 && b->d[0] == 0))
		ပြန်ပေး 0;
	/* Find MSB set */
	w = b->d[b->top];
	bits = (b->top + 1) * BITMAP_BITS;
	နေစဉ် (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	ပြန်ပေး bits;
}

size_t
bitmap_nbytes(sa_nracanaa bitmap *b)
{
	ပြန်ပေး (bitmap_nbits(b) + 7) / 8;
}

ကိန်းပြည့်
bitmap_to_string(sa_nracanaa bitmap *b, void *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	အကယ်၍ (l < need || b->top >= b->len)
		ပြန်ပေး -1;
	အကယ်၍ (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	အတွက် (i = k = 0; i < b->top + 1; i++) {
		အတွက် (j = 0; j < BITMAP_BYTES; j++) {
			အကယ်၍ (k >= l)
				bha_nga;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	ပြန်ပေး 0;
}

ကိန်းပြည့်
bitmap_from_string(sa_nracanaa bitmap *b, const void *p, size_t l)
{
	ကိန်းပြည့် r;
	size_t i, offset, shift;
	const u_char *s = (const u_char *)p;

	အကယ်၍ (l > BITMAP_MAX / 8)
		ပြန်ပေး -1;
	အကယ်၍ ((r = reserve(b, l * 8)) != 0)
		ပြန်ပေး r;
	bitmap_zero(b);
	အကယ်၍ (l == 0)
		ပြန်ပေး 0;
	b->top = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	အတွက် (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		အကယ်၍ (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} မဟုတ်ပါက
			shift -= 8;
	}
	retop(b);
	ပြန်ပေး 0;
}
