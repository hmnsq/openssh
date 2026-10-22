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

#अगर_अघोषित _DIGEST_H
#घोषणा _DIGEST_H

/* Maximum digest output length */
#घोषणा SSH_DIGEST_MAX_लंबाई	64

/* Digest algorithms */
#घोषणा SSH_DIGEST_MD5		0
#घोषणा SSH_DIGEST_SHA1		1
#घोषणा SSH_DIGEST_SHA256	2
#घोषणा SSH_DIGEST_SHA384	3
#घोषणा SSH_DIGEST_SHA512	4
#घोषणा SSH_DIGEST_MAX		5

काष्ठा sshbuf;
काष्ठा ssh_digest_ctx;

/* Looks up a digest algorithm by name */
पूर्णांक ssh_digest_alg_by_name(स्थिर अक्षर *name);

/* Returns the algorithm name for a digest identifier */
स्थिर अक्षर *ssh_digest_alg_name(पूर्णांक alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
माप_प्रकार ssh_digest_bytes(पूर्णांक alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
माप_प्रकार ssh_digest_blocksize(काष्ठा ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
पूर्णांक ssh_digest_copy_state(काष्ठा ssh_digest_ctx *from,
    काष्ठा ssh_digest_ctx *to);

/* One-shot API */
पूर्णांक ssh_digest_memory(पूर्णांक alg, स्थिर व्योम *m, माप_प्रकार mlen,
    u_char *d, माप_प्रकार dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
पूर्णांक ssh_digest_बफर(पूर्णांक alg, स्थिर काष्ठा sshbuf *b, u_char *d, माप_प्रकार dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
काष्ठा ssh_digest_ctx *ssh_digest_start(पूर्णांक alg);
पूर्णांक ssh_digest_update(काष्ठा ssh_digest_ctx *ctx, स्थिर व्योम *m, माप_प्रकार mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
पूर्णांक ssh_digest_update_बफर(काष्ठा ssh_digest_ctx *ctx,
    स्थिर काष्ठा sshbuf *b);
पूर्णांक ssh_digest_final(काष्ठा ssh_digest_ctx *ctx, u_char *d, माप_प्रकार dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
व्योम ssh_digest_free(काष्ठा ssh_digest_ctx *ctx);

#पूर्ण_अगर /* _DIGEST_H */

