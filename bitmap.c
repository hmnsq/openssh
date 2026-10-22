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
#define BITMAP_BYTES	(आकार(BITMAP_WTYPE))
#define BITMAP_BITS	(आकार(BITMAP_WTYPE) * 8)
#define BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
संरचना bitmap {
	BITMAP_WTYPE *d;
	माप_प्रकार len; /* number of words allocated */
	माप_प्रकार शीर्ष; /* index of top word allocated */
};

संरचना bitmap *
bitmap_new(शून्य)
{
	संरचना bitmap *ret;

	जर ((ret = सुस्मृति(1, आकार(*ret))) == रिक्त)
		परत रिक्त;
	जर ((ret->d = सुस्मृति(1, BITMAP_BYTES)) == रिक्त) {
		मुक्त(ret);
		परत रिक्त;
	}
	ret->len = 1;
	ret->शीर्ष = 0;
	परत ret;
}

शून्य
bitmap_free(संरचना bitmap *b)
{
	जर (b != रिक्त && b->d != रिक्त) {
		bitmap_zero(b);
		मुक्त(b->d);
		b->d = रिक्त;
	}
	मुक्त(b);
}

शून्य
bitmap_zero(संरचना bitmap *b)
{
	स_रखो(b->d, 0, b->len * BITMAP_BYTES);
	b->शीर्ष = 0;
}

पूर्णांक
bitmap_test_bit(संरचना bitmap *b, u_int n)
{
	जर (b->शीर्ष >= b->len)
		परत 0; /* invalid */
	जर (b->len == 0 || (n / BITMAP_BITS) > b->शीर्ष)
		परत 0;
	परत (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

स्थिर पूर्णांक
reserve(संरचना bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	माप_प्रकार nlen;

	जर (b->शीर्ष >= b->len || n > BITMAP_MAX)
		परत -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	जर (b->len < nlen) {
		जर ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == रिक्त)
			परत -1;
		b->d = tmp;
		b->len = nlen;
	}
	परत 0;
}

पूर्णांक
bitmap_set_bit(संरचना bitmap *b, u_int n)
{
	पूर्णांक r;
	माप_प्रकार offset;

	जर ((r = reserve(b, n)) != 0)
		परत r;
	offset = n / BITMAP_BITS;
	जर (offset > b->शीर्ष)
		b->शीर्ष = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	परत 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
स्थिर शून्य
retop(संरचना bitmap *b)
{
	जर (b->शीर्ष >= b->len)
		परत;
	पर्यंत (b->शीर्ष > 0 && b->d[b->शीर्ष] == 0)
		b->शीर्ष--;
}

शून्य
bitmap_clear_bit(संरचना bitmap *b, u_int n)
{
	माप_प्रकार offset;

	जर (b->शीर्ष >= b->len || n > BITMAP_MAX)
		परत; /* invalid */
	offset = n / BITMAP_BITS;
	जर (offset > b->शीर्ष)
		परत;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

माप_प्रकार
bitmap_nbits(संरचना bitmap *b)
{
	माप_प्रकार bits;
	BITMAP_WTYPE w;

	retop(b);
	जर (b->शीर्ष >= b->len)
		परत 0; /* invalid */
	जर (b->len == 0 || (b->शीर्ष == 0 && b->d[0] == 0))
		परत 0;
	/* Find MSB set */
	w = b->d[b->शीर्ष];
	bits = (b->शीर्ष + 1) * BITMAP_BITS;
	पर्यंत (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	परत bits;
}

माप_प्रकार
bitmap_nbytes(संरचना bitmap *b)
{
	परत (bitmap_nbits(b) + 7) / 8;
}

पूर्णांक
bitmap_to_string(संरचना bitmap *b, शून्य *p, माप_प्रकार l)
{
	u_char *s = (u_char *)p;
	माप_प्रकार i, j, k, need = bitmap_nbytes(b);

	जर (l < need || b->शीर्ष >= b->len)
		परत -1;
	जर (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	साठी (i = k = 0; i < b->शीर्ष + 1; i++) {
		साठी (j = 0; j < BITMAP_BYTES; j++) {
			जर (k >= l)
				थांबा;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	परत 0;
}

पूर्णांक
bitmap_from_string(संरचना bitmap *b, स्थिरांक शून्य *p, माप_प्रकार l)
{
	पूर्णांक r;
	माप_प्रकार i, offset, shift;
	स्थिरांक u_char *s = (स्थिरांक u_char *)p;

	जर (l > BITMAP_MAX / 8)
		परत -1;
	जर ((r = reserve(b, l * 8)) != 0)
		परत r;
	bitmap_zero(b);
	जर (l == 0)
		परत 0;
	b->शीर्ष = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	साठी (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		जर (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} अन्यथा
			shift -= 8;
	}
	retop(b);
	परत 0;
}
