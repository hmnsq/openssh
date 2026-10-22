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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <string.h>
#समावेश <stdlib.h>

#समावेश "bitmap.h"

#घोषणा BITMAP_WTYPE	u_int
#घोषणा BITMAP_MAX	(1<<24)
#घोषणा BITMAP_BYTES	(माप(BITMAP_WTYPE))
#घोषणा BITMAP_BITS	(माप(BITMAP_WTYPE) * 8)
#घोषणा BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_BITS - 1)
काष्ठा bitmap {
	BITMAP_WTYPE *d;
	माप_प्रकार len; /* number of words allocated */
	माप_प्रकार शीर्ष; /* index of top word allocated */
};

काष्ठा bitmap *
bitmap_new(व्योम)
{
	काष्ठा bitmap *ret;

	अगर ((ret = सुस्मृति(1, माप(*ret))) == शून्य)
		वापस शून्य;
	अगर ((ret->d = सुस्मृति(1, BITMAP_BYTES)) == शून्य) {
		मुक्त(ret);
		वापस शून्य;
	}
	ret->len = 1;
	ret->शीर्ष = 0;
	वापस ret;
}

व्योम
bitmap_free(काष्ठा bitmap *b)
{
	अगर (b != शून्य && b->d != शून्य) {
		bitmap_zero(b);
		मुक्त(b->d);
		b->d = शून्य;
	}
	मुक्त(b);
}

व्योम
bitmap_zero(काष्ठा bitmap *b)
{
	स_रखो(b->d, 0, b->len * BITMAP_BYTES);
	b->शीर्ष = 0;
}

पूर्णांक
bitmap_test_bit(काष्ठा bitmap *b, u_int n)
{
	अगर (b->शीर्ष >= b->len)
		वापस 0; /* invalid */
	अगर (b->len == 0 || (n / BITMAP_BITS) > b->शीर्ष)
		वापस 0;
	वापस (b->d[n / BITMAP_BITS] >> (n & BITMAP_WMASK)) & 1;
}

अटल पूर्णांक
reserve(काष्ठा bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	माप_प्रकार nlen;

	अगर (b->शीर्ष >= b->len || n > BITMAP_MAX)
		वापस -1; /* invalid */
	nlen = (n / BITMAP_BITS) + 1;
	अगर (b->len < nlen) {
		अगर ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_BYTES)) == शून्य)
			वापस -1;
		b->d = tmp;
		b->len = nlen;
	}
	वापस 0;
}

पूर्णांक
bitmap_set_bit(काष्ठा bitmap *b, u_int n)
{
	पूर्णांक r;
	माप_प्रकार offset;

	अगर ((r = reserve(b, n)) != 0)
		वापस r;
	offset = n / BITMAP_BITS;
	अगर (offset > b->शीर्ष)
		b->शीर्ष = offset;
	b->d[offset] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	वापस 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
अटल व्योम
retop(काष्ठा bitmap *b)
{
	अगर (b->शीर्ष >= b->len)
		वापस;
	जबतक (b->शीर्ष > 0 && b->d[b->शीर्ष] == 0)
		b->शीर्ष--;
}

व्योम
bitmap_clear_bit(काष्ठा bitmap *b, u_int n)
{
	माप_प्रकार offset;

	अगर (b->शीर्ष >= b->len || n > BITMAP_MAX)
		वापस; /* invalid */
	offset = n / BITMAP_BITS;
	अगर (offset > b->शीर्ष)
		वापस;
	b->d[offset] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

माप_प्रकार
bitmap_nbits(काष्ठा bitmap *b)
{
	माप_प्रकार bits;
	BITMAP_WTYPE w;

	retop(b);
	अगर (b->शीर्ष >= b->len)
		वापस 0; /* invalid */
	अगर (b->len == 0 || (b->शीर्ष == 0 && b->d[0] == 0))
		वापस 0;
	/* Find MSB set */
	w = b->d[b->शीर्ष];
	bits = (b->शीर्ष + 1) * BITMAP_BITS;
	जबतक (!(w & ((BITMAP_WTYPE)1 << (BITMAP_BITS - 1)))) {
		w <<= 1;
		bits--;
	}
	वापस bits;
}

माप_प्रकार
bitmap_nbytes(काष्ठा bitmap *b)
{
	वापस (bitmap_nbits(b) + 7) / 8;
}

पूर्णांक
bitmap_to_string(काष्ठा bitmap *b, व्योम *p, माप_प्रकार l)
{
	u_char *s = (u_char *)p;
	माप_प्रकार i, j, k, need = bitmap_nbytes(b);

	अगर (l < need || b->शीर्ष >= b->len)
		वापस -1;
	अगर (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	क्रम (i = k = 0; i < b->शीर्ष + 1; i++) {
		क्रम (j = 0; j < BITMAP_BYTES; j++) {
			अगर (k >= l)
				अवरोध;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	वापस 0;
}

पूर्णांक
bitmap_from_string(काष्ठा bitmap *b, स्थिर व्योम *p, माप_प्रकार l)
{
	पूर्णांक r;
	माप_प्रकार i, offset, shift;
	स्थिर u_char *s = (स्थिर u_char *)p;

	अगर (l > BITMAP_MAX / 8)
		वापस -1;
	अगर ((r = reserve(b, l * 8)) != 0)
		वापस r;
	bitmap_zero(b);
	अगर (l == 0)
		वापस 0;
	b->शीर्ष = offset = ((l + (BITMAP_BYTES - 1)) / BITMAP_BYTES) - 1;
	shift = ((l + (BITMAP_BYTES - 1)) % BITMAP_BYTES) * 8;
	क्रम (i = 0; i < l; i++) {
		b->d[offset] |= (BITMAP_WTYPE)s[i] << shift;
		अगर (shift == 0) {
			offset--;
			shift = BITMAP_BITS - 8;
		} अन्यथा
			shift -= 8;
	}
	retop(b);
	वापस 0;
}
