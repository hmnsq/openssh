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

संरचना sshbuf;
संरचना ssh_digest_ctx;

/* Looks up a digest algorithm by name */
पूर्णाङ्क ssh_digest_alg_by_name(अचर वर्ण *name);

/* Returns the algorithm name for a digest identifier */
अचर वर्ण *ssh_digest_alg_name(पूर्णाङ्क alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
माप_प्रकार ssh_digest_bytes(पूर्णाङ्क alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
माप_प्रकार ssh_digest_blocksize(संरचना ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
पूर्णाङ्क ssh_digest_copy_state(संरचना ssh_digest_ctx *from,
    संरचना ssh_digest_ctx *to);

/* One-shot API */
पूर्णाङ्क ssh_digest_memory(पूर्णाङ्क alg, अचर शून्य *m, माप_प्रकार mlen,
    u_char *d, माप_प्रकार dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
पूर्णाङ्क ssh_digest_buffer(पूर्णाङ्क alg, अचर संरचना sshbuf *b, u_char *d, माप_प्रकार dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
संरचना ssh_digest_ctx *ssh_digest_start(पूर्णाङ्क alg);
पूर्णाङ्क ssh_digest_update(संरचना ssh_digest_ctx *ctx, अचर शून्य *m, माप_प्रकार mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
पूर्णाङ्क ssh_digest_update_buffer(संरचना ssh_digest_ctx *ctx,
    अचर संरचना sshbuf *b);
पूर्णाङ्क ssh_digest_final(संरचना ssh_digest_ctx *ctx, u_char *d, माप_प्रकार dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
शून्य ssh_digest_free(संरचना ssh_digest_ctx *ctx);

#endif /* _DIGEST_H */

