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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _DIGEST_H
#ವ್ಯಾಖ್ಯಾನಿಸು _DIGEST_H

/* Maximum digest output length */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_DIGEST_MAX_ಉದ್ದಳತೆ	64

/* Digest algorithms */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_DIGEST_MD5		0
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_DIGEST_SHA1		1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_DIGEST_SHA256	2
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_DIGEST_SHA384	3
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_DIGEST_SHA512	4
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_DIGEST_MAX		5

ರಚನೆ sshbuf;
ರಚನೆ ssh_digest_ctx;

/* Looks up a digest algorithm by name */
ಪೂರ್ಣಾಂಕ ssh_digest_alg_by_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);

/* Returns the algorithm name for a digest identifier */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ssh_digest_alg_name(ಪೂರ್ಣಾಂಕ alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
ಗಾತ್ರ_t ssh_digest_ಬೈಟುಗಳು(ಪೂರ್ಣಾಂಕ alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
ಗಾತ್ರ_t ssh_digest_blocksize(ರಚನೆ ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
ಪೂರ್ಣಾಂಕ ssh_digest_copy_state(ರಚನೆ ssh_digest_ctx *from,
    ರಚನೆ ssh_digest_ctx *ಗಮ್ಯ);

/* One-shot API */
ಪೂರ್ಣಾಂಕ ssh_digest_ಸ್ಮರಣೆ(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *m, ಗಾತ್ರ_t mlen,
    u_char *d, ಗಾತ್ರ_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
ಪೂರ್ಣಾಂಕ ssh_digest_ಬಫರ್(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b, u_char *d, ಗಾತ್ರ_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
ರಚನೆ ssh_digest_ctx *ssh_digest_ಆರಂಭ(ಪೂರ್ಣಾಂಕ alg);
ಪೂರ್ಣಾಂಕ ssh_digest_update(ರಚನೆ ssh_digest_ctx *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *m, ಗಾತ್ರ_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ಪೂರ್ಣಾಂಕ ssh_digest_update_ಬಫರ್(ರಚನೆ ssh_digest_ctx *ctx,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b);
ಪೂರ್ಣಾಂಕ ssh_digest_final(ರಚನೆ ssh_digest_ctx *ctx, u_char *d, ಗಾತ್ರ_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ಶೂನ್ಯ ssh_digest_free(ರಚನೆ ssh_digest_ctx *ctx);

#ಆದರೆ_ಅಂತ್ಯ /* _DIGEST_H */

