/* $OpenBSD: hmac.h,v 1.9 2014/06/24 01:13:21 djm Exp $ */
/*
 * Copyright (c) 2014 Markus Friedl.  All rights reserved.
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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _HMAC_H
#ವ್ಯಾಖ್ಯಾನಿಸು _HMAC_H

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
ಗಾತ್ರ_t ssh_hmac_ಬೈಟುಗಳು(ಪೂರ್ಣಾಂಕ alg);

ರಚನೆ sshbuf;
ರಚನೆ ssh_hmac_ctx;
ರಚನೆ ssh_hmac_ctx *ssh_hmac_ಆರಂಭ(ಪೂರ್ಣಾಂಕ alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
ಪೂರ್ಣಾಂಕ ssh_hmac_init(ರಚನೆ ssh_hmac_ctx *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಕೀಲಿ, ಗಾತ್ರ_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ಪೂರ್ಣಾಂಕ ssh_hmac_update(ರಚನೆ ssh_hmac_ctx *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *m, ಗಾತ್ರ_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ಪೂರ್ಣಾಂಕ ssh_hmac_update_ಬಫರ್(ರಚನೆ ssh_hmac_ctx *ctx, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b);
ಪೂರ್ಣಾಂಕ ssh_hmac_final(ರಚನೆ ssh_hmac_ctx *ctx, u_char *d, ಗಾತ್ರ_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ಶೂನ್ಯ ssh_hmac_free(ರಚನೆ ssh_hmac_ctx *ctx);

#ಆದರೆ_ಅಂತ್ಯ /* _HMAC_H */
