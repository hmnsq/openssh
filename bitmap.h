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

#ifndef _BITMAP_H
#define _BITMAP_H

#অন্তর্ভাব <sys/types.h>

/* Simple bit vector routines */

সংরচনা bitmap;

/* Allocate a new bitmap. Returns NULL on allocation failure. */
সংরচনা bitmap *bitmap_new(শূন্য);

/* Free a bitmap */
শূন্য bitmap_free(সংরচনা bitmap *b);

/* Zero an existing bitmap */
শূন্য bitmap_zero(সংরচনা bitmap *b);

/* Test whether a bit is set in a bitmap. */
পূর্ণাঙ্ক bitmap_test_bit(সংরচনা bitmap *b, u_int n);

/* Set a bit in a bitmap. Returns 0 on success or -1 on error */
পূর্ণাঙ্ক bitmap_set_bit(সংরচনা bitmap *b, u_int n);

/* Clear a bit in a bitmap */
শূন্য bitmap_clear_bit(সংরচনা bitmap *b, u_int n);

/* Return the number of bits in a bitmap (i.e. the position of the MSB) */
size_t bitmap_nbits(সংরচনা bitmap *b);

/* Return the number of bytes needed to represent a bitmap */
size_t bitmap_nbytes(সংরচনা bitmap *b);

/* Convert a bitmap to a big endian byte string */
পূর্ণাঙ্ক bitmap_to_string(সংরচনা bitmap *b, শূন্য *p, size_t l);

/* Convert a big endian byte string to a bitmap */
পূর্ণাঙ্ক bitmap_from_string(সংরচনা bitmap *b, ধ্রুব শূন্য *p, size_t l);

#endif /* _BITMAP_H */
