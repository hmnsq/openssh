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

ساختار sshbuf;
ساختار ssh_digest_ctx;

/* Looks up a digest algorithm by name */
صحیح ssh_digest_alg_by_name(ثابت نویسه *name);

/* Returns the algorithm name for a digest identifier */
ثابت نویسه *ssh_digest_alg_name(صحیح alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
size_t ssh_digest_bytes(صحیح alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
size_t ssh_digest_blocksize(ساختار ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
صحیح ssh_digest_copy_state(ساختار ssh_digest_ctx *from,
    ساختار ssh_digest_ctx *to);

/* One-shot API */
صحیح ssh_digest_memory(صحیح alg, ثابت تهی *m, size_t mlen,
    u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
صحیح ssh_digest_buffer(صحیح alg, ثابت ساختار sshbuf *b, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
ساختار ssh_digest_ctx *ssh_digest_start(صحیح alg);
صحیح ssh_digest_update(ساختار ssh_digest_ctx *ctx, ثابت تهی *m, size_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
صحیح ssh_digest_update_buffer(ساختار ssh_digest_ctx *ctx,
    ثابت ساختار sshbuf *b);
صحیح ssh_digest_final(ساختار ssh_digest_ctx *ctx, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
تهی ssh_digest_free(ساختار ssh_digest_ctx *ctx);

#endif /* _DIGEST_H */

