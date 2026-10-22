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

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

/* Simple bit vector routines */

ସଂରଚନା bitmap;

/* Allocate a new bitmap. Returns NULL on allocation failure. */
ସଂରଚନା bitmap *bitmap_new(ଶୂନ୍ୟ);

/* Free a bitmap */
ଶୂନ୍ୟ bitmap_free(ସଂରଚନା bitmap *b);

/* Zero an existing bitmap */
ଶୂନ୍ୟ bitmap_zero(ସଂରଚନା bitmap *b);

/* Test whether a bit is set in a bitmap. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା bitmap_test_bit(ସଂରଚନା bitmap *b, u_int n);

/* Set a bit in a bitmap. Returns 0 on success or -1 on error */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା bitmap_set_bit(ସଂରଚନା bitmap *b, u_int n);

/* Clear a bit in a bitmap */
ଶୂନ୍ୟ bitmap_clear_bit(ସଂରଚନା bitmap *b, u_int n);

/* Return the number of bits in a bitmap (i.e. the position of the MSB) */
size_t bitmap_nbits(ସଂରଚନା bitmap *b);

/* Return the number of bytes needed to represent a bitmap */
size_t bitmap_nbytes(ସଂରଚନା bitmap *b);

/* Convert a bitmap to a big endian byte string */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା bitmap_to_string(ସଂରଚନା bitmap *b, ଶୂନ୍ୟ *p, size_t l);

/* Convert a big endian byte string to a bitmap */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା bitmap_from_string(ସଂରଚନା bitmap *b, ଅଚଳ ଶୂନ୍ୟ *p, size_t l);

#endif /* _BITMAP_H */
