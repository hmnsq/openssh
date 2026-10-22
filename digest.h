/* $OpenBSD: digest.h,v 1.8 2017/05/08 22:57:38 djm Exp $ */
/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

#నిర్వచితం_కాకపోతే _DIGEST_H
#నిర్వచించు _DIGEST_H

/* Maximum digest output length */
#నిర్వచించు SSH_DIGEST_MAX_నిడివి	64

/* Digest algorithms */
#నిర్వచించు SSH_DIGEST_MD5		0
#నిర్వచించు SSH_DIGEST_SHA1		1
#నిర్వచించు SSH_DIGEST_SHA256	2
#నిర్వచించు SSH_DIGEST_SHA384	3
#నిర్వచించు SSH_DIGEST_SHA512	4
#నిర్వచించు SSH_DIGEST_MAX		5

నిర్మాణం sshbuf;
నిర్మాణం ssh_digest_ctx;

/* Looks up a digest algorithm by name */
పూర్ణాంకం ssh_digest_alg_by_name(స్థిరరాశి అక్షరం *name);

/* Returns the algorithm name for a digest identifier */
స్థిరరాశి అక్షరం *ssh_digest_alg_name(పూర్ణాంకం alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
కొలత_t ssh_digest_బైట్లు(పూర్ణాంకం alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
కొలత_t ssh_digest_blocksize(నిర్మాణం ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
పూర్ణాంకం ssh_digest_copy_state(నిర్మాణం ssh_digest_ctx *from,
    నిర్మాణం ssh_digest_ctx *గమ్యం);

/* One-shot API */
పూర్ణాంకం ssh_digest_జ్ఞాపకం(పూర్ణాంకం alg, స్థిరరాశి శూన్య *m, కొలత_t mlen,
    u_char *d, కొలత_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
పూర్ణాంకం ssh_digest_బఫరు(పూర్ణాంకం alg, స్థిరరాశి నిర్మాణం sshbuf *b, u_char *d, కొలత_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
నిర్మాణం ssh_digest_ctx *ssh_digest_ప్రారంభం(పూర్ణాంకం alg);
పూర్ణాంకం ssh_digest_update(నిర్మాణం ssh_digest_ctx *ctx, స్థిరరాశి శూన్య *m, కొలత_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
పూర్ణాంకం ssh_digest_update_బఫరు(నిర్మాణం ssh_digest_ctx *ctx,
    స్థిరరాశి నిర్మాణం sshbuf *b);
పూర్ణాంకం ssh_digest_final(నిర్మాణం ssh_digest_ctx *ctx, u_char *d, కొలత_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
శూన్య ssh_digest_free(నిర్మాణం ssh_digest_ctx *ctx);

#అయితే_ముగింపు /* _DIGEST_H */

