/* $OpenBSD: hmac.h,v 1.9 2014/06/24 01:13:21 djm Exp $ */
/*
 * Copyright (c) 2014 Markus Friedl.  All rights reserved.
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

#నిర్వచితం_కాకపోతే _HMAC_H
#నిర్వచించు _HMAC_H

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
కొలత_t ssh_hmac_బైట్లు(పూర్ణాంకం alg);

నిర్మాణం sshbuf;
నిర్మాణం ssh_hmac_ctx;
నిర్మాణం ssh_hmac_ctx *ssh_hmac_ప్రారంభం(పూర్ణాంకం alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
పూర్ణాంకం ssh_hmac_init(నిర్మాణం ssh_hmac_ctx *ctx, స్థిరరాశి శూన్య *కీలకం, కొలత_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
పూర్ణాంకం ssh_hmac_update(నిర్మాణం ssh_hmac_ctx *ctx, స్థిరరాశి శూన్య *m, కొలత_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
పూర్ణాంకం ssh_hmac_update_బఫరు(నిర్మాణం ssh_hmac_ctx *ctx, స్థిరరాశి నిర్మాణం sshbuf *b);
పూర్ణాంకం ssh_hmac_final(నిర్మాణం ssh_hmac_ctx *ctx, u_char *d, కొలత_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
శూన్య ssh_hmac_free(నిర్మాణం ssh_hmac_ctx *ctx);

#అయితే_ముగింపు /* _HMAC_H */
