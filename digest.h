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
#define SSH_DIGEST_MAX_দৈর্ঘ্য	64

/* Digest algorithms */
#define SSH_DIGEST_MD5		0
#define SSH_DIGEST_SHA1		1
#define SSH_DIGEST_SHA256	2
#define SSH_DIGEST_SHA384	3
#define SSH_DIGEST_SHA512	4
#define SSH_DIGEST_MAX		5

কাঠামো sshbuf;
কাঠামো ssh_digest_ctx;

/* Looks up a digest algorithm by name */
পূর্ণসংখ্যা ssh_digest_alg_by_name(ধ্রুবক অক্ষর *name);

/* Returns the algorithm name for a digest identifier */
ধ্রুবক অক্ষর *ssh_digest_alg_name(পূর্ণসংখ্যা alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
আকার_t ssh_digest_bytes(পূর্ণসংখ্যা alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
আকার_t ssh_digest_blocksize(কাঠামো ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
পূর্ণসংখ্যা ssh_digest_copy_state(কাঠামো ssh_digest_ctx *from,
    কাঠামো ssh_digest_ctx *to);

/* One-shot API */
পূর্ণসংখ্যা ssh_digest_memory(পূর্ণসংখ্যা alg, ধ্রুবক শূন্য *m, আকার_t mlen,
    u_char *d, আকার_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
পূর্ণসংখ্যা ssh_digest_বাফার(পূর্ণসংখ্যা alg, ধ্রুবক কাঠামো sshbuf *b, u_char *d, আকার_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
কাঠামো ssh_digest_ctx *ssh_digest_start(পূর্ণসংখ্যা alg);
পূর্ণসংখ্যা ssh_digest_update(কাঠামো ssh_digest_ctx *ctx, ধ্রুবক শূন্য *m, আকার_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
পূর্ণসংখ্যা ssh_digest_update_বাফার(কাঠামো ssh_digest_ctx *ctx,
    ধ্রুবক কাঠামো sshbuf *b);
পূর্ণসংখ্যা ssh_digest_final(কাঠামো ssh_digest_ctx *ctx, u_char *d, আকার_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
শূন্য ssh_digest_free(কাঠামো ssh_digest_ctx *ctx);

#endif /* _DIGEST_H */

