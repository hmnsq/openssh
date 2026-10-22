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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <string.h>
#ضمن <stdlib.h>

#ضمن "bitmap.h"

#تعریف_کړه BITMAP_WTYPE	u_int
#تعریف_کړه BITMAP_MAX	(1<<24)
#تعریف_کړه BITMAP_بایټونه	(حجم(BITMAP_WTYPE))
#تعریف_کړه BITMAP_بټونه	(حجم(BITMAP_WTYPE) * 8)
#تعریف_کړه BITMAP_WMASK	((BITMAP_WTYPE)BITMAP_بټونه - 1)
بنية bitmap {
	BITMAP_WTYPE *d;
	اندازه_t len; /* number of words allocated */
	اندازه_t سر; /* index of top word allocated */
};

بنية bitmap *
bitmap_new(فراغ)
{
	بنية bitmap *ret;

	إذا ((ret = حافظه_صفر_ورکړه(1, حجم(*ret))) == عدم)
		أرجع عدم;
	إذا ((ret->d = حافظه_صفر_ورکړه(1, BITMAP_بایټونه)) == عدم) {
		حرر(ret);
		أرجع عدم;
	}
	ret->len = 1;
	ret->سر = 0;
	أرجع ret;
}

فراغ
bitmap_free(بنية bitmap *b)
{
	إذا (b != عدم && b->d != عدم) {
		bitmap_zero(b);
		حرر(b->d);
		b->d = عدم;
	}
	حرر(b);
}

فراغ
bitmap_zero(بنية bitmap *b)
{
	memset(b->d, 0, b->len * BITMAP_بایټونه);
	b->سر = 0;
}

صحيح
bitmap_test_بټ(بنية bitmap *b, u_int n)
{
	إذا (b->سر >= b->len)
		أرجع 0; /* invalid */
	إذا (b->len == 0 || (n / BITMAP_بټونه) > b->سر)
		أرجع 0;
	أرجع (b->d[n / BITMAP_بټونه] >> (n & BITMAP_WMASK)) & 1;
}

ساكن صحيح
reserve(بنية bitmap *b, u_int n)
{
	BITMAP_WTYPE *tmp;
	اندازه_t nlen;

	إذا (b->سر >= b->len || n > BITMAP_MAX)
		أرجع -1; /* invalid */
	nlen = (n / BITMAP_بټونه) + 1;
	إذا (b->len < nlen) {
		إذا ((tmp = recallocarray(b->d, b->len,
		    nlen, BITMAP_بایټونه)) == عدم)
			أرجع -1;
		b->d = tmp;
		b->len = nlen;
	}
	أرجع 0;
}

صحيح
bitmap_سېټ_بټ(بنية bitmap *b, u_int n)
{
	صحيح r;
	اندازه_t دننه_واټن;

	إذا ((r = reserve(b, n)) != 0)
		أرجع r;
	دننه_واټن = n / BITMAP_بټونه;
	إذا (دننه_واټن > b->سر)
		b->سر = دننه_واټن;
	b->d[دننه_واټن] |= (BITMAP_WTYPE)1 << (n & BITMAP_WMASK);
	أرجع 0;
}

/* Resets b->top to point to the most significant bit set in b->d */
ساكن فراغ
retop(بنية bitmap *b)
{
	إذا (b->سر >= b->len)
		أرجع;
	طالما (b->سر > 0 && b->d[b->سر] == 0)
		b->سر--;
}

فراغ
bitmap_clear_بټ(بنية bitmap *b, u_int n)
{
	اندازه_t دننه_واټن;

	إذا (b->سر >= b->len || n > BITMAP_MAX)
		أرجع; /* invalid */
	دننه_واټن = n / BITMAP_بټونه;
	إذا (دننه_واټن > b->سر)
		أرجع;
	b->d[دننه_واټن] &= ~((BITMAP_WTYPE)1 << (n & BITMAP_WMASK));
	/* The top may have changed as a result of the clear */
	retop(b);
}

اندازه_t
bitmap_nbits(بنية bitmap *b)
{
	اندازه_t بټونه;
	BITMAP_WTYPE w;

	retop(b);
	إذا (b->سر >= b->len)
		أرجع 0; /* invalid */
	إذا (b->len == 0 || (b->سر == 0 && b->d[0] == 0))
		أرجع 0;
	/* Find MSB set */
	w = b->d[b->سر];
	بټونه = (b->سر + 1) * BITMAP_بټونه;
	طالما (!(w & ((BITMAP_WTYPE)1 << (BITMAP_بټونه - 1)))) {
		w <<= 1;
		بټونه--;
	}
	أرجع بټونه;
}

اندازه_t
bitmap_nbytes(بنية bitmap *b)
{
	أرجع (bitmap_nbits(b) + 7) / 8;
}

صحيح
bitmap_منزل_string(بنية bitmap *b, فراغ *p, اندازه_t l)
{
	u_char *s = (u_char *)p;
	اندازه_t i, j, k, need = bitmap_nbytes(b);

	إذا (l < need || b->سر >= b->len)
		أرجع -1;
	إذا (l > need)
		l = need;
	/* Put the bytes from LSB backwards */
	لكل (i = k = 0; i < b->سر + 1; i++) {
		لكل (j = 0; j < BITMAP_بایټونه; j++) {
			إذا (k >= l)
				اكسر;
			s[need - 1 - k++] = (b->d[i] >> (j * 8)) & 0xff;
		}
	}
	أرجع 0;
}

صحيح
bitmap_from_string(بنية bitmap *b, ثابت فراغ *p, اندازه_t l)
{
	صحيح r;
	اندازه_t i, دننه_واټن, ښويدنه;
	ثابت u_char *s = (ثابت u_char *)p;

	إذا (l > BITMAP_MAX / 8)
		أرجع -1;
	إذا ((r = reserve(b, l * 8)) != 0)
		أرجع r;
	bitmap_zero(b);
	إذا (l == 0)
		أرجع 0;
	b->سر = دننه_واټن = ((l + (BITMAP_بایټونه - 1)) / BITMAP_بایټونه) - 1;
	ښويدنه = ((l + (BITMAP_بایټونه - 1)) % BITMAP_بایټونه) * 8;
	لكل (i = 0; i < l; i++) {
		b->d[دننه_واټن] |= (BITMAP_WTYPE)s[i] << ښويدنه;
		إذا (ښويدنه == 0) {
			دننه_واټن--;
			ښويدنه = BITMAP_بټونه - 8;
		} وإلا
			ښويدنه -= 8;
	}
	retop(b);
	أرجع 0;
}
