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

#నిర్వచితం_కాకపోతే _BITMAP_H
#నిర్వచించు _BITMAP_H

#అన్తర్భావ <sys/types.h>

/* Simple bit vector routines */

నిర్మాణం bitmap;

/* Allocate a new bitmap. Returns NULL on allocation failure. */
నిర్మాణం bitmap *bitmap_new(శూన్య);

/* Free a bitmap */
శూన్య bitmap_free(నిర్మాణం bitmap *b);

/* Zero an existing bitmap */
శూన్య bitmap_zero(నిర్మాణం bitmap *b);

/* Test whether a bit is set in a bitmap. */
పూర్ణాంకం bitmap_test_బిట్టు(నిర్మాణం bitmap *b, u_int n);

/* Set a bit in a bitmap. Returns 0 on success or -1 on error */
పూర్ణాంకం bitmap_సమితి_బిట్టు(నిర్మాణం bitmap *b, u_int n);

/* Clear a bit in a bitmap */
శూన్య bitmap_clear_బిట్టు(నిర్మాణం bitmap *b, u_int n);

/* Return the number of bits in a bitmap (i.e. the position of the MSB) */
కొలత_t bitmap_nbits(నిర్మాణం bitmap *b);

/* Return the number of bytes needed to represent a bitmap */
కొలత_t bitmap_nbytes(నిర్మాణం bitmap *b);

/* Convert a bitmap to a big endian byte string */
పూర్ణాంకం bitmap_గమ్యం_string(నిర్మాణం bitmap *b, శూన్య *p, కొలత_t l);

/* Convert a big endian byte string to a bitmap */
పూర్ణాంకం bitmap_from_string(నిర్మాణం bitmap *b, స్థిరరాశి శూన్య *p, కొలత_t l);

#అయితే_ముగింపు /* _BITMAP_H */
