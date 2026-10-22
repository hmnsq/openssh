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

#اگر_غیر_تعریف_شدہ _BITMAP_H
#تعریف_کرو _BITMAP_H

#شامل <sys/types.h>

/* Simple bit vector routines */

ساخت bitmap;

/* Allocate a new bitmap. Returns NULL on allocation failure. */
ساخت bitmap *bitmap_new(خالی);

/* Free a bitmap */
خالی bitmap_free(ساخت bitmap *b);

/* Zero an existing bitmap */
خالی bitmap_zero(ساخت bitmap *b);

/* Test whether a bit is set in a bitmap. */
صحیح bitmap_test_ثنائی_ہندسہ(ساخت bitmap *b, u_int n);

/* Set a bit in a bitmap. Returns 0 on success or -1 on error */
صحیح bitmap_سیٹ_ثنائی_ہندسہ(ساخت bitmap *b, u_int n);

/* Clear a bit in a bitmap */
خالی bitmap_clear_ثنائی_ہندسہ(ساخت bitmap *b, u_int n);

/* Return the number of bits in a bitmap (i.e. the position of the MSB) */
سائز_t bitmap_nbits(ساخت bitmap *b);

/* Return the number of bytes needed to represent a bitmap */
سائز_t bitmap_nbytes(ساخت bitmap *b);

/* Convert a bitmap to a big endian byte string */
صحیح bitmap_مقصد_string(ساخت bitmap *b, خالی *p, سائز_t l);

/* Convert a big endian byte string to a bitmap */
صحیح bitmap_from_string(ساخت bitmap *b, ثابت خالی *p, سائز_t l);

#اگر_ختم /* _BITMAP_H */
