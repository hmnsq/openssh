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

#اگر_غیر_تعریف_شدہ _DIGEST_H
#تعریف_کرو _DIGEST_H

/* Maximum digest output length */
#تعریف_کرو SSH_DIGEST_MAX_لمبائی	64

/* Digest algorithms */
#تعریف_کرو SSH_DIGEST_MD5		0
#تعریف_کرو SSH_DIGEST_SHA1		1
#تعریف_کرو SSH_DIGEST_SHA256	2
#تعریف_کرو SSH_DIGEST_SHA384	3
#تعریف_کرو SSH_DIGEST_SHA512	4
#تعریف_کرو SSH_DIGEST_MAX		5

ساخت sshbuf;
ساخت ssh_digest_ctx;

/* Looks up a digest algorithm by name */
صحیح ssh_digest_alg_by_name(ثابت حرف *name);

/* Returns the algorithm name for a digest identifier */
ثابت حرف *ssh_digest_alg_name(صحیح alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
سائز_t ssh_digest_بائٹیں(صحیح alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
سائز_t ssh_digest_blocksize(ساخت ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
صحیح ssh_digest_copy_state(ساخت ssh_digest_ctx *from,
    ساخت ssh_digest_ctx *مقصد);

/* One-shot API */
صحیح ssh_digest_حافظہ(صحیح alg, ثابت خالی *m, سائز_t mlen,
    u_char *d, سائز_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
صحیح ssh_digest_بفر(صحیح alg, ثابت ساخت sshbuf *b, u_char *d, سائز_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
ساخت ssh_digest_ctx *ssh_digest_آغاز(صحیح alg);
صحیح ssh_digest_update(ساخت ssh_digest_ctx *ctx, ثابت خالی *m, سائز_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
صحیح ssh_digest_update_بفر(ساخت ssh_digest_ctx *ctx,
    ثابت ساخت sshbuf *b);
صحیح ssh_digest_final(ساخت ssh_digest_ctx *ctx, u_char *d, سائز_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
خالی ssh_digest_free(ساخت ssh_digest_ctx *ctx);

#اگر_ختم /* _DIGEST_H */

