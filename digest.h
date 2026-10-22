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

#ifndef _DIGEST_H
#define _DIGEST_H

/* Maximum digest output length */
#define SSH_DIGEST_MAX_LENGTH	64

/* Digest algorithms */
#define SSH_DIGEST_MD5		0
#define SSH_DIGEST_SHA1		1
#define SSH_DIGEST_SHA256	2
#define SSH_DIGEST_SHA384	3
#define SSH_DIGEST_SHA512	4
#define SSH_DIGEST_MAX		5

ಸಂರಚನಾ sshbuf;
ಸಂರಚನಾ ssh_digest_ctx;

/* Looks up a digest algorithm by name */
ಪೂರ್ಣಾಙ್ಕ ssh_digest_alg_by_name(ಧ್ರುವ ವರ್ಣ *name);

/* Returns the algorithm name for a digest identifier */
ಧ್ರುವ ವರ್ಣ *ssh_digest_alg_name(ಪೂರ್ಣಾಙ್ಕ alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
size_t ssh_digest_bytes(ಪೂರ್ಣಾಙ್ಕ alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
size_t ssh_digest_blocksize(ಸಂರಚನಾ ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
ಪೂರ್ಣಾಙ್ಕ ssh_digest_copy_state(ಸಂರಚನಾ ssh_digest_ctx *from,
    ಸಂರಚನಾ ssh_digest_ctx *to);

/* One-shot API */
ಪೂರ್ಣಾಙ್ಕ ssh_digest_memory(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ ಶೂನ್ಯ *m, size_t mlen,
    u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
ಪೂರ್ಣಾಙ್ಕ ssh_digest_buffer(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
ಸಂರಚನಾ ssh_digest_ctx *ssh_digest_start(ಪೂರ್ಣಾಙ್ಕ alg);
ಪೂರ್ಣಾಙ್ಕ ssh_digest_update(ಸಂರಚನಾ ssh_digest_ctx *ctx, ಧ್ರುವ ಶೂನ್ಯ *m, size_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ಪೂರ್ಣಾಙ್ಕ ssh_digest_update_buffer(ಸಂರಚನಾ ssh_digest_ctx *ctx,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *b);
ಪೂರ್ಣಾಙ್ಕ ssh_digest_final(ಸಂರಚನಾ ssh_digest_ctx *ctx, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ಶೂನ್ಯ ssh_digest_free(ಸಂರಚನಾ ssh_digest_ctx *ctx);

#endif /* _DIGEST_H */

