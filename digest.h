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

#اگر_تعریف_نشده _DIGEST_H
#تعریف_کن _DIGEST_H

/* Maximum digest output length */
#تعریف_کن SSH_DIGEST_MAX_درازی	64

/* Digest algorithms */
#تعریف_کن SSH_DIGEST_MD5		0
#تعریف_کن SSH_DIGEST_SHA1		1
#تعریف_کن SSH_DIGEST_SHA256	2
#تعریف_کن SSH_DIGEST_SHA384	3
#تعریف_کن SSH_DIGEST_SHA512	4
#تعریف_کن SSH_DIGEST_MAX		5

بنية sshbuf;
بنية ssh_digest_ctx;

/* Looks up a digest algorithm by name */
صحيح ssh_digest_alg_by_name(ثابت حرف *name);

/* Returns the algorithm name for a digest identifier */
ثابت حرف *ssh_digest_alg_name(صحيح alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
اندازه_t ssh_digest_بایتها(صحيح alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
اندازه_t ssh_digest_blocksize(بنية ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
صحيح ssh_digest_copy_state(بنية ssh_digest_ctx *from,
    بنية ssh_digest_ctx *مقصد);

/* One-shot API */
صحيح ssh_digest_حافظه(صحيح alg, ثابت فراغ *m, اندازه_t mlen,
    u_char *d, اندازه_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
صحيح ssh_digest_میانگیر(صحيح alg, ثابت بنية sshbuf *b, u_char *d, اندازه_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
بنية ssh_digest_ctx *ssh_digest_شروع(صحيح alg);
صحيح ssh_digest_update(بنية ssh_digest_ctx *ctx, ثابت فراغ *m, اندازه_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
صحيح ssh_digest_update_میانگیر(بنية ssh_digest_ctx *ctx,
    ثابت بنية sshbuf *b);
صحيح ssh_digest_final(بنية ssh_digest_ctx *ctx, u_char *d, اندازه_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
فراغ ssh_digest_free(بنية ssh_digest_ctx *ctx);

#پایان_اگر /* _DIGEST_H */

