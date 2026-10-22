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

#परिभाषय BITMAP_WTYPE	u_int
#परिभाषय BITMAP_MAX	(1<<24)
#परिभाषय BITMAP_अष्टकानि	(परिमाण(BITMAP_WTYPE))
#परिभाषय BITMAP_द्वयङ्काः	(परिमाण(BITMAP_WTYPE) * 8)
#परिभाषय BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_द्वयङ्काः - 1)
संरचना bitmap {
	BITMAP_WTYPE *d;
	आकार_t len; /* number of words allocated */
	आकार_t शिखरम्; /* index of top word allocated */
};

संरचना bitmap *
bitmap_new(शून्य)
{
	संरचना bitmap *ret;

	यदि ((ret = शून्यस्मृतिं_देहि(1, परिमाण(*ret))) == रिक्त)
		प्रत्यागम रिक्त;
	यदि ((ret->d = शून्यस्मृतिं_देहि(1, BITMAP_अष्टकानि)) == रिक्त) {
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
	यदि (b != रिक्त && b->d != रिक्त) {
		bitmap_zero(b);
		मुक्त(b->d);
		b->d = रिक्त;
	}
	मुक्त(b);
}

शून्य
bitmap_zero(संरचना bitmap *b)
{
	स्मृतिं_पूरय(b->d, 0, b->len * BITMAP_अष्टकानि);
	b->शिखरम् = 0;
}

पूर्णाङ्क
bitmap_test_bit(संरचना bitmap *b, u_int n)
{
	यदि (b->शिखरम् >= b->len)
		प्रत्यागम 0; /* invalid */
	यदि (b->len == 0 || (n / BITMAP_द्वयङ्काः) > b->शिखरम्)
		प्रत्यागम 0;
	प्रत्यागम (b->d[n / BITMAP_द्वयङ्काः] >> (n & BITMAP_WMASK)) & 1;
}

स्थिर पूर्णाङ्क
reserve(संरचना bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	आकार_t nlen;

	यदि (b->शिखरम् >= b->len || n > BITMAP_MAX)
		प्रत्यागम -1; /* invalid */
	nlen = (n / BITMAP_द्वयङ्काः) + 1;
	यदि (b->len < nlen) {
		यदि ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_अष्टकानि)) == रिक्त)
			प्रत्यागम -1;
		b->d = tmp;
		b->len = nlen;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
bitmap_समुच्चयः_bit(संरचना bitmap *b, u_int n)
{
	पूर्णाङ्क r;
	आकार_t विस्थापनम्;

	यदि ((r = reserve(b, n)) != 0)
		प्रत्यागम r;
	विस्थापनम् = n / BITMAP_द्वयङ्काः;
	यदि (विस्थापनम् > b->शिखरम्)
		b->शिखरम् = विस्थापनम्;
	b->d[विस्थापनम्] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	प्रत्यागम 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
स्थिर शून्य
retop(संरचना bitmap *b)
{
	यदि (b->शिखरम् >= b->len)
		प्रत्यागम;
	यावत् (b->शिखरम् > 0 && b->d[b->शिखरम्] == 0)
		b->शिखरम्--;
}

शून्य
bitmap_clear_bit(संरचना bitmap *b, u_int n)
{
	आकार_t विस्थापनम्;

	यदि (b->शिखरम् >= b->len || n > BITMAP_MAX)
		प्रत्यागम; /* invalid */
	विस्थापनम् = n / BITMAP_द्वयङ्काः;
	यदि (विस्थापनम् > b->शिखरम्)
		प्रत्यागम;
	b->d[विस्थापनम्] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

आकार_t
bitmap_nbits(संरचना bitmap *b)
{
	आकार_t द्वयङ्काः;
	BITMAP_WTYPE w;

	retop(b);
	यदि (b->शिखरम् >= b->len)
		प्रत्यागम 0; /* invalid */
	यदि (b->len == 0 || (b->शिखरम् == 0 && b->d[0] == 0))
		प्रत्यागम 0;
	/* Find MSB set */
	w = b->d[b->शिखरम्];
	द्वयङ्काः = (b->शिखरम् + 1) * BITMAP_द्वयङ्काः;
	यावत् (!(w & ((BITMAP_WTYPE)1 << (BITMAP_द्वयङ्काः - 1)))) {
		w <<= 1;
		द्वयङ्काः--;
	}
	प्रत्यागम द्वयङ्काः;
}

आकार_t
bitmap_nbytes(संरचना bitmap *b)
{
	प्रत्यागम (bitmap_nbits(b) + 7) / 8;
}

पूर्णाङ्क
bitmap_गन्तव्यम्_string(संरचना bitmap *b, शून्य *p, आकार_t l)
{
	u_char *s = (u_char *)p;
	आकार_t i, j, k, need = bitmap_nbytes(b);

	यदि (l < need || b->शिखरम् >= b->len)
		प्रत्यागम -1;
	यदि (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	प्रति (i = k = 0; i < b->शिखरम् + 1; i++) {
		प्रति (j = 0; j < BITMAP_अष्टकानि; j++) {
			यदि (k >= l)
				भङ्ग;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
bitmap_from_string(संरचना bitmap *b, ध्रुव शून्य *p, आकार_t l)
{
	पूर्णाङ्क r;
	आकार_t i, विस्थापनम्, सरणम्;
	ध्रुव u_char *s = (ध्रुव u_char *)p;

	यदि (l > BITMAP_MAX / 8)
		प्रत्यागम -1;
	यदि ((r = reserve(b, l * 8)) != 0)
		प्रत्यागम r;
	bitmap_zero(b);
	यदि (l == 0)
		प्रत्यागम 0;
	b->शिखरम् = विस्थापनम् = ((l + (BITMAP_अष्टकानि - 1)) / BITMAP_अष्टकानि) - 1;
	सरणम् = ((l + (BITMAP_अष्टकानि - 1)) % BITMAP_अष्टकानि) * 8;
	प्रति (i = 0; i < l; i++) {
		b->d[विस्थापनम्] |= (BITMAP_WTYPE)s[i] << सरणम्;
		यदि (सरणम् == 0) {
			विस्थापनम्--;
			सरणम् = BITMAP_द्वयङ्काः - 8;
		} अन्यथा
			सरणम् -= 8;
	}
	retop(b);
	प्रत्यागम 0;
}
