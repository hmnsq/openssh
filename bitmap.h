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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _BITMAP_H
#ವ್ಯಾಖ್ಯಾನಿಸು _BITMAP_H

#ಅನ್ತರ್ಭಾವ <sys/types.h>

/* Simple bit vector routines */

ರಚನೆ bitmap;

/* Allocate a new bitmap. Returns NULL on allocation failure. */
ರಚನೆ bitmap *bitmap_new(ಶೂನ್ಯ);

/* Free a bitmap */
ಶೂನ್ಯ bitmap_free(ರಚನೆ bitmap *b);

/* Zero an existing bitmap */
ಶೂನ್ಯ bitmap_zero(ರಚನೆ bitmap *b);

/* Test whether a bit is set in a bitmap. */
ಪೂರ್ಣಾಂಕ bitmap_test_ಬಿಟ್(ರಚನೆ bitmap *b, u_int n);

/* Set a bit in a bitmap. Returns 0 on success or -1 on error */
ಪೂರ್ಣಾಂಕ bitmap_ಗಣ_ಬಿಟ್(ರಚನೆ bitmap *b, u_int n);

/* Clear a bit in a bitmap */
ಶೂನ್ಯ bitmap_clear_ಬಿಟ್(ರಚನೆ bitmap *b, u_int n);

/* Return the number of bits in a bitmap (i.e. the position of the MSB) */
ಗಾತ್ರ_t bitmap_nbits(ರಚನೆ bitmap *b);

/* Return the number of bytes needed to represent a bitmap */
ಗಾತ್ರ_t bitmap_nbytes(ರಚನೆ bitmap *b);

/* Convert a bitmap to a big endian byte string */
ಪೂರ್ಣಾಂಕ bitmap_ಗಮ್ಯ_string(ರಚನೆ bitmap *b, ಶೂನ್ಯ *p, ಗಾತ್ರ_t l);

/* Convert a big endian byte string to a bitmap */
ಪೂರ್ಣಾಂಕ bitmap_from_string(ರಚನೆ bitmap *b, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *p, ಗಾತ್ರ_t l);

#ಆದರೆ_ಅಂತ್ಯ /* _BITMAP_H */
