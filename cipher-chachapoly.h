/* $OpenBSD: cipher-chachapoly.h,v 1.5 2020/04/03 04:27:03 djm Exp $ */

/*
 * Copyright (c) Damien Miller 2013 <djm@mindrot.org>
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
#నిర్వచితం_కాకపోతే CHACHA_POLY_AEAD_H
#నిర్వచించు CHACHA_POLY_AEAD_H

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ "chacha.h"
#అన్తర్భావ "poly1305.h"

#నిర్వచించు CHACHA_KEYLEN	32 /* Only 256 bit keys used here */

నిర్మాణం chachapoly_ctx;

నిర్మాణం chachapoly_ctx *chachapoly_new(స్థిరరాశి u_char *కీలకం, u_int keylen)
    __attribute__((__bounded__(__buffer__, 1, 2)));
శూన్య chachapoly_free(నిర్మాణం chachapoly_ctx *cpctx);

పూర్ణాంకం	chachapoly_crypt(నిర్మాణం chachapoly_ctx *cpctx, u_int seqnr,
    u_char *dest, స్థిరరాశి u_char *src, u_int len, u_int aadlen, u_int authlen,
    పూర్ణాంకం do_encrypt);
పూర్ణాంకం	chachapoly_get_నిడివి(నిర్మాణం chachapoly_ctx *cpctx,
    u_int *plenp, u_int seqnr, స్థిరరాశి u_char *cp, u_int len)
    __attribute__((__bounded__(__buffer__, 4, 5)));

#అయితే_ముగింపు /* CHACHA_POLY_AEAD_H */
