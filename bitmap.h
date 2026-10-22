/* $OpenBSD: bitmap.h,v 1.2 2017/10/20 01:56:39 djm Exp $ */
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

#اگر_تعریف_نشده _BITMAP_H
#تعریف_کن _BITMAP_H

#ضمن <sys/types.h>

/* Simple bit vector routines */

بنية bitmap;

/* Allocate a new bitmap. Returns NULL on allocation failure. */
بنية bitmap *bitmap_new(فراغ);

/* Free a bitmap */
فراغ bitmap_free(بنية bitmap *b);

/* Zero an existing bitmap */
فراغ bitmap_zero(بنية bitmap *b);

/* Test whether a bit is set in a bitmap. */
صحيح bitmap_test_بیت(بنية bitmap *b, u_int n);

/* Set a bit in a bitmap. Returns 0 on success or -1 on error */
صحيح bitmap_مجموعه_بیت(بنية bitmap *b, u_int n);

/* Clear a bit in a bitmap */
فراغ bitmap_clear_بیت(بنية bitmap *b, u_int n);

/* Return the number of bits in a bitmap (i.e. the position of the MSB) */
اندازه_t bitmap_nbits(بنية bitmap *b);

/* Return the number of bytes needed to represent a bitmap */
اندازه_t bitmap_nbytes(بنية bitmap *b);

/* Convert a bitmap to a big endian byte string */
صحيح bitmap_مقصد_string(بنية bitmap *b, فراغ *p, اندازه_t l);

/* Convert a big endian byte string to a bitmap */
صحيح bitmap_from_string(بنية bitmap *b, ثابت فراغ *p, اندازه_t l);

#پایان_اگر /* _BITMAP_H */
