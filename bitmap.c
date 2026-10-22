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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

#अन्तर्भाव "bitmap.h"

#define BITMAP_WTYPE	u_int
#define BITMAP_MAX	(1<<24)
#define BITMAP_BYTES	(परिमाण(BITMAP_WTYPE))
#define BITMAP_BITS	(परिमाण(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
संरचना bitmap {
	BITMAP_WTYPE *d;
	size_t len; /* number of words allocated */
	size_t शिखरम्; /* index of top word allocated */
};

संरचना bitmap *
bitmap_new(शून्य)
{
	संरचना bitmap *ret;

	जइ ((ret = calloc(1, परिमाण(*ret))) == रिक्त)
		प्रत्यागम रिक्त;
	जइ ((ret->d = calloc(1, BITMAP_BYTES)) == रिक्त) {
		मुक्त(ret);
		प्रत्यागम रिक्त;
	}
	ret->len = 1;
	ret->शिखरम् = 0;
	प्रत्यागम ret;
}

शून्य
bitmap_free(संरचना bitmap *b)
{
	जइ (b != रिक्त && b->d != रिक्त) {
		bitmap_zero(b);
		मुक्त(b->d);
		b->d = रिक्त;
	}
	मुक्त(b);
}

शून्य
bitmap_zero(संरचना bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_BYTES);
	b->शिखरम् = 0;
}

पूर्णाङ्क
bitmap_test_bit(संरचना bitmap *b, u_int n)
{
	जइ (b->शिखरम् >= b->len)
		प्रत्यागम 0; /* invalid */
	जइ (b->len == 0 || (n / BITMAP_BITS) > b->शिखरम्)
		प्रत्यागम 0;
	प्रत्यागम (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

स्थिर पूर्णाङ्क
reserve(संरचना bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	size_t nlen;

	जइ (b->शिखरम् >= b->len || n > BITMAP_MAX)
		प्रत्यागम -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	जइ (b->len < nlen) {
		जइ ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == रिक्त)
			प्रत्यागम -1;
		b->d = tmp;
		b->len = nlen;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
bitmap_set_bit(संरचना bitmap *b, u_int n)
{
	पूर्णाङ्क r;
	size_t offset;

	जइ ((r = reserve(b, n)) != 0)
		प्रत्यागम r;
	offset = n / BITMAP_BITS;
	जइ (offset > b->शिखरम्)
		b->शिखरम् = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	प्रत्यागम 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
स्थिर शून्य
retop(संरचना bitmap *b)
{
	जइ (b->शिखरम् >= b->len)
		प्रत्यागम;
	जाव (b->शिखरम् > 0 && b->d[b->शिखरम्] == 0)
		b->शिखरम्--;
}

शून्य
bitmap_clear_bit(संरचना bitmap *b, u_int n)
{
	size_t offset;

	जइ (b->शिखरम् >= b->len || n > BITMAP_MAX)
		प्रत्यागम; /* invalid */
	offset = n / BITMAP_BITS;
	जइ (offset > b->शिखरम्)
		प्रत्यागम;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

size_t
bitmap_nbits(संरचना bitmap *b)
{
	size_t bits;
	BITMAP_WTYPE w;

	retop(b);
	जइ (b->शिखरम् >= b->len)
		प्रत्यागम 0; /* invalid */
	जइ (b->len == 0 || (b->शिखरम् == 0 && b->d[0] == 0))
		प्रत्यागम 0;
	/* Find MSB set */
	w = b->d[b->शिखरम्];
	bits = (b->शिखरम् + 1) * BITMAP_BITS;
	जाव (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	प्रत्यागम bits;
}

size_t
bitmap_nbytes(संरचना bitmap *b)
{
	प्रत्यागम (bitmap_nbits(b) + 7) / 8;
}

पूर्णाङ्क
bitmap_to_string(संरचना bitmap *b, शून्य *p, size_t l)
{
	u_char *s = (u_char *)p;
	size_t i, j, k, need = bitmap_nbytes(b);

	जइ (l < need || b->शिखरम् >= b->len)
		प्रत्यागम -1;
	जइ (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	प्रति (i = k = 0; i < b->शिखरम् + 1; i++) {
		प्रति (j = 0; j < BITMAP_BYTES; j++) {
			जइ (k >= l)
				भङ्ग;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
bitmap_from_string(संरचना bitmap *b, ध्रुव शून्य *p, size_t l)
{
	पूर्णाङ्क r;
	size_t i, offset, shift;
	ध्रुव u_char *s = (ध्रुव u_char *)p;

	जइ (l > BITMAP_MAX / 8)
		प्रत्यागम -1;
	जइ ((r = reserve(b, l * 8)) != 0)
		प्रत्यागम r;
	bitmap_zero(b);
	जइ (l == 0)
		प्रत्यागम 0;
	b->शिखरम् = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	प्रति (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		जइ (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} अण्णहा
			shift -= 8;
	}
	retop(b);
	प्रत्यागम 0;
}
