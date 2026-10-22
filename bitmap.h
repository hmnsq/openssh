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

#अगर_अघोषित _BITMAP_H
#घोषणा _BITMAP_H

#समावेश <sys/types.h>

/* Simple bit vector routines */

काष्ठा bitmap;

/* Allocate a new bitmap. Returns NULL on allocation failure. */
काष्ठा bitmap *bitmap_new(व्योम);

/* Free a bitmap */
व्योम bitmap_free(काष्ठा bitmap *b);

/* Zero an existing bitmap */
व्योम bitmap_zero(काष्ठा bitmap *b);

/* Test whether a bit is set in a bitmap. */
पूर्णांक bitmap_test_bit(काष्ठा bitmap *b, u_int n);

/* Set a bit in a bitmap. Returns 0 on success or -1 on error */
पूर्णांक bitmap_set_bit(काष्ठा bitmap *b, u_int n);

/* Clear a bit in a bitmap */
व्योम bitmap_clear_bit(काष्ठा bitmap *b, u_int n);

/* Return the number of bits in a bitmap (i.e. the position of the MSB) */
माप_प्रकार bitmap_nbits(काष्ठा bitmap *b);

/* Return the number of bytes needed to represent a bitmap */
माप_प्रकार bitmap_nbytes(काष्ठा bitmap *b);

/* Convert a bitmap to a big endian byte string */
पूर्णांक bitmap_to_string(काष्ठा bitmap *b, व्योम *p, माप_प्रकार l);

/* Convert a big endian byte string to a bitmap */
पूर्णांक bitmap_from_string(काष्ठा bitmap *b, स्थिर व्योम *p, माप_प्रकार l);

#पूर्ण_अगर /* _BITMAP_H */
