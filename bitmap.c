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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdlib.h>

#అన్తర్భావ "bitmap.h"

#నిర్వచించు BITMAP_WTYPE	u_int
#నిర్వచించు BITMAP_MAX	(1<<24)
#నిర్వచించు BITMAP_బైట్లు	(పరిమాణం(BITMAP_WTYPE))
#నిర్వచించు BITMAP_బిట్లు	(పరిమాణం(BITMAP_WTYPE) * 8)
#నిర్వచించు BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_బిట్లు - 1)
నిర్మాణం bitmap {
	BITMAP_WTYPE *d;
	కొలత_t len; /* number of words allocated */
	కొలత_t శిఖరం; /* index of top word allocated */
};

నిర్మాణం bitmap *
bitmap_new(శూన్య)
{
	నిర్మాణం bitmap *ret;

	ఒకవేళ ((ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret))) == ఖాళీ)
		తిరిగి ఖాళీ;
	ఒకవేళ ((ret->d = సున్నా_జ్ఞాపకం_ఇవ్వు(1, BITMAP_బైట్లు)) == ఖాళీ) {
		విడుదల(ret);
		తిరిగి ఖాళీ;
	}
	ret->len = 1;
	ret->శిఖరం = 0;
	తిరిగి ret;
}

శూన్య
bitmap_free(నిర్మాణం bitmap *b)
{
	ఒకవేళ (b != ఖాళీ && b->d != ఖాళీ) {
		bitmap_zero(b);
		విడుదల(b->d);
		b->d = ఖాళీ;
	}
	విడుదల(b);
}

శూన్య
bitmap_zero(నిర్మాణం bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_బైట్లు);
	b->శిఖరం = 0;
}

పూర్ణాంకం
bitmap_test_బిట్టు(నిర్మాణం bitmap *b, u_int n)
{
	ఒకవేళ (b->శిఖరం >= b->len)
		తిరిగి 0; /* invalid */
	ఒకవేళ (b->len == 0 || (n / BITMAP_బిట్లు) > b->శిఖరం)
		తిరిగి 0;
	తిరిగి (b->d[n / BITMAP_బిట్లు] >> (n & BITMAP_WMASK)) & 1;
}

స్థిర పూర్ణాంకం
reserve(నిర్మాణం bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	కొలత_t nlen;

	ఒకవేళ (b->శిఖరం >= b->len || n > BITMAP_MAX)
		తిరిగి -1; /* invalid */
	nlen = (n / BITMAP_బిట్లు) + 1;
	ఒకవేళ (b->len < nlen) {
		ఒకవేళ ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_బైట్లు)) == ఖాళీ)
			తిరిగి -1;
		b->d = tmp;
		b->len = nlen;
	}
	తిరిగి 0;
}

పూర్ణాంకం
bitmap_సమితి_బిట్టు(నిర్మాణం bitmap *b, u_int n)
{
	పూర్ణాంకం r;
	కొలత_t స్థానభ్రంశం;

	ఒకవేళ ((r = reserve(b, n)) != 0)
		తిరిగి r;
	స్థానభ్రంశం = n / BITMAP_బిట్లు;
	ఒకవేళ (స్థానభ్రంశం > b->శిఖరం)
		b->శిఖరం = స్థానభ్రంశం;
	b->d[స్థానభ్రంశం] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	తిరిగి 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
స్థిర శూన్య
retop(నిర్మాణం bitmap *b)
{
	ఒకవేళ (b->శిఖరం >= b->len)
		తిరిగి;
	అయితే (b->శిఖరం > 0 && b->d[b->శిఖరం] == 0)
		b->శిఖరం--;
}

శూన్య
bitmap_clear_బిట్టు(నిర్మాణం bitmap *b, u_int n)
{
	కొలత_t స్థానభ్రంశం;

	ఒకవేళ (b->శిఖరం >= b->len || n > BITMAP_MAX)
		తిరిగి; /* invalid */
	స్థానభ్రంశం = n / BITMAP_బిట్లు;
	ఒకవేళ (స్థానభ్రంశం > b->శిఖరం)
		తిరిగి;
	b->d[స్థానభ్రంశం] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

కొలత_t
bitmap_nbits(నిర్మాణం bitmap *b)
{
	కొలత_t బిట్లు;
	BITMAP_WTYPE w;

	retop(b);
	ఒకవేళ (b->శిఖరం >= b->len)
		తిరిగి 0; /* invalid */
	ఒకవేళ (b->len == 0 || (b->శిఖరం == 0 && b->d[0] == 0))
		తిరిగి 0;
	/* Find MSB set */
	w = b->d[b->శిఖరం];
	బిట్లు = (b->శిఖరం + 1) * BITMAP_బిట్లు;
	అయితే (!(w & ((BITMAP_WTYPE)1 << (BITMAP_బిట్లు - 1)))) {
		w <<= 1;
		బిట్లు--;
	}
	తిరిగి బిట్లు;
}

కొలత_t
bitmap_nbytes(నిర్మాణం bitmap *b)
{
	తిరిగి (bitmap_nbits(b) + 7) / 8;
}

పూర్ణాంకం
bitmap_గమ్యం_string(నిర్మాణం bitmap *b, శూన్య *p, కొలత_t l)
{
	u_char *s = (u_char *)p;
	కొలత_t i, j, k, need = bitmap_nbytes(b);

	ఒకవేళ (l < need || b->శిఖరం >= b->len)
		తిరిగి -1;
	ఒకవేళ (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	కొరకు (i = k = 0; i < b->శిఖరం + 1; i++) {
		కొరకు (j = 0; j < BITMAP_బైట్లు; j++) {
			ఒకవేళ (k >= l)
				ఆపు;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	తిరిగి 0;
}

పూర్ణాంకం
bitmap_from_string(నిర్మాణం bitmap *b, స్థిరరాశి శూన్య *p, కొలత_t l)
{
	పూర్ణాంకం r;
	కొలత_t i, స్థానభ్రంశం, జరుపు;
	స్థిరరాశి u_char *s = (స్థిరరాశి u_char *)p;

	ఒకవేళ (l > BITMAP_MAX / 8)
		తిరిగి -1;
	ఒకవేళ ((r = reserve(b, l * 8)) != 0)
		తిరిగి r;
	bitmap_zero(b);
	ఒకవేళ (l == 0)
		తిరిగి 0;
	b->శిఖరం = స్థానభ్రంశం = ((l + (BITMAP_బైట్లు - 1)) / BITMAP_బైట్లు) - 1;
	జరుపు = ((l + (BITMAP_బైట్లు - 1)) % BITMAP_బైట్లు) * 8;
	కొరకు (i = 0; i < l; i++) {
		b->d[స్థానభ్రంశం] |= (BITMAP_WTYPE)s[i] << జరుపు;
		ఒకవేళ (జరుపు == 0) {
			స్థానభ్రంశం--;
			జరుపు = BITMAP_బిట్లు - 8;
		} లేకపోతే
			జరుపు -= 8;
	}
	retop(b);
	తిరిగి 0;
}
