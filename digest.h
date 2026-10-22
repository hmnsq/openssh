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

ସଂରଚନା sshbuf;
ସଂରଚନା ssh_digest_ctx;

/* Looks up a digest algorithm by name */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_digest_alg_by_name(ଅଚଳ ଅକ୍ଷର *name);

/* Returns the algorithm name for a digest identifier */
ଅଚଳ ଅକ୍ଷର *ssh_digest_alg_name(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
size_t ssh_digest_bytes(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
size_t ssh_digest_blocksize(ସଂରଚନା ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_digest_copy_state(ସଂରଚନା ssh_digest_ctx *from,
    ସଂରଚନା ssh_digest_ctx *to);

/* One-shot API */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_digest_memory(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ ଶୂନ୍ୟ *m, size_t mlen,
    u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_digest_buffer(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ ସଂରଚନା sshbuf *b, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
ସଂରଚନା ssh_digest_ctx *ssh_digest_start(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_digest_update(ସଂରଚନା ssh_digest_ctx *ctx, ଅଚଳ ଶୂନ୍ୟ *m, size_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_digest_update_buffer(ସଂରଚନା ssh_digest_ctx *ctx,
    ଅଚଳ ସଂରଚନା sshbuf *b);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_digest_final(ସଂରଚନା ssh_digest_ctx *ctx, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ଶୂନ୍ୟ ssh_digest_free(ସଂରଚନା ssh_digest_ctx *ctx);

#endif /* _DIGEST_H */

