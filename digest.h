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

#جيڪڏهن_وصف_نه_ٿيل _DIGEST_H
#وصف_ڪريو _DIGEST_H

/* Maximum digest output length */
#وصف_ڪريو SSH_DIGEST_MAX_ڊيگهائي	64

/* Digest algorithms */
#وصف_ڪريو SSH_DIGEST_MD5		0
#وصف_ڪريو SSH_DIGEST_SHA1		1
#وصف_ڪريو SSH_DIGEST_SHA256	2
#وصف_ڪريو SSH_DIGEST_SHA384	3
#وصف_ڪريو SSH_DIGEST_SHA512	4
#وصف_ڪريو SSH_DIGEST_MAX		5

بنية sshbuf;
بنية ssh_digest_ctx;

/* Looks up a digest algorithm by name */
صحيح ssh_digest_alg_by_name(ثابت حرف *name);

/* Returns the algorithm name for a digest identifier */
ثابت حرف *ssh_digest_alg_name(صحيح alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
سائيز_t ssh_digest_بائيٽون(صحيح alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
سائيز_t ssh_digest_blocksize(بنية ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
صحيح ssh_digest_copy_state(بنية ssh_digest_ctx *from,
    بنية ssh_digest_ctx *منزل);

/* One-shot API */
صحيح ssh_digest_يادگيري(صحيح alg, ثابت فراغ *m, سائيز_t mlen,
    u_char *d, سائيز_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
صحيح ssh_digest_بفر(صحيح alg, ثابت بنية sshbuf *b, u_char *d, سائيز_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
بنية ssh_digest_ctx *ssh_digest_شروعات(صحيح alg);
صحيح ssh_digest_update(بنية ssh_digest_ctx *ctx, ثابت فراغ *m, سائيز_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
صحيح ssh_digest_update_بفر(بنية ssh_digest_ctx *ctx,
    ثابت بنية sshbuf *b);
صحيح ssh_digest_final(بنية ssh_digest_ctx *ctx, u_char *d, سائيز_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
فراغ ssh_digest_free(بنية ssh_digest_ctx *ctx);

#جيڪڏهن_پورو /* _DIGEST_H */

