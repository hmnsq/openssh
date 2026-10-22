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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _BITMAP_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _BITMAP_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

/* Simple bit vector routines */

ਬਣਤਰ bitmap;

/* Allocate a new bitmap. Returns NULL on allocation failure. */
ਬਣਤਰ bitmap *bitmap_new(ਖਾਲੀ);

/* Free a bitmap */
ਖਾਲੀ bitmap_free(ਬਣਤਰ bitmap *b);

/* Zero an existing bitmap */
ਖਾਲੀ bitmap_zero(ਬਣਤਰ bitmap *b);

/* Test whether a bit is set in a bitmap. */
ਪੂਰਨ bitmap_test_ਦੋਆਧਾਰੀ_ਅੰਕ(ਬਣਤਰ bitmap *b, u_int n);

/* Set a bit in a bitmap. Returns 0 on success or -1 on error */
ਪੂਰਨ bitmap_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(ਬਣਤਰ bitmap *b, u_int n);

/* Clear a bit in a bitmap */
ਖਾਲੀ bitmap_clear_ਦੋਆਧਾਰੀ_ਅੰਕ(ਬਣਤਰ bitmap *b, u_int n);

/* Return the number of bits in a bitmap (i.e. the position of the MSB) */
ਮਾਪ_t bitmap_nbits(ਬਣਤਰ bitmap *b);

/* Return the number of bytes needed to represent a bitmap */
ਮਾਪ_t bitmap_nbytes(ਬਣਤਰ bitmap *b);

/* Convert a bitmap to a big endian byte string */
ਪੂਰਨ bitmap_ਮੰਜ਼ਿਲ_string(ਬਣਤਰ bitmap *b, ਖਾਲੀ *p, ਮਾਪ_t l);

/* Convert a big endian byte string to a bitmap */
ਪੂਰਨ bitmap_from_string(ਬਣਤਰ bitmap *b, ਅਚਲ ਖਾਲੀ *p, ਮਾਪ_t l);

#ਜੇ_ਅੰਤ /* _BITMAP_H */
