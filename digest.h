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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _DIGEST_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _DIGEST_H

/* Maximum digest output length */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_DIGEST_MAX_ਲੰਮਾਈ	64

/* Digest algorithms */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_DIGEST_MD5		0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_DIGEST_SHA1		1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_DIGEST_SHA256	2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_DIGEST_SHA384	3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_DIGEST_SHA512	4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_DIGEST_MAX		5

ਬਣਤਰ sshbuf;
ਬਣਤਰ ssh_digest_ctx;

/* Looks up a digest algorithm by name */
ਪੂਰਨ ssh_digest_alg_by_name(ਅਚਲ ਅੱਖਰ *name);

/* Returns the algorithm name for a digest identifier */
ਅਚਲ ਅੱਖਰ *ssh_digest_alg_name(ਪੂਰਨ alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
ਮਾਪ_t ssh_digest_ਬਾਈਟਾਂ(ਪੂਰਨ alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
ਮਾਪ_t ssh_digest_blocksize(ਬਣਤਰ ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
ਪੂਰਨ ssh_digest_copy_state(ਬਣਤਰ ssh_digest_ctx *from,
    ਬਣਤਰ ssh_digest_ctx *ਮੰਜ਼ਿਲ);

/* One-shot API */
ਪੂਰਨ ssh_digest_ਸਮ੍ਰਿਤੀ(ਪੂਰਨ alg, ਅਚਲ ਖਾਲੀ *m, ਮਾਪ_t mlen,
    u_char *d, ਮਾਪ_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
ਪੂਰਨ ssh_digest_ਬਫਰ(ਪੂਰਨ alg, ਅਚਲ ਬਣਤਰ sshbuf *b, u_char *d, ਮਾਪ_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
ਬਣਤਰ ssh_digest_ctx *ssh_digest_ਸ਼ੁਰੂ(ਪੂਰਨ alg);
ਪੂਰਨ ssh_digest_update(ਬਣਤਰ ssh_digest_ctx *ctx, ਅਚਲ ਖਾਲੀ *m, ਮਾਪ_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ਪੂਰਨ ssh_digest_update_ਬਫਰ(ਬਣਤਰ ssh_digest_ctx *ctx,
    ਅਚਲ ਬਣਤਰ sshbuf *b);
ਪੂਰਨ ssh_digest_final(ਬਣਤਰ ssh_digest_ctx *ctx, u_char *d, ਮਾਪ_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ਖਾਲੀ ssh_digest_free(ਬਣਤਰ ssh_digest_ctx *ctx);

#ਜੇ_ਅੰਤ /* _DIGEST_H */

