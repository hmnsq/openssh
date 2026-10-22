/* $OpenBSD: cipher-chachapoly.h,v 1.5 2020/04/03 04:27:03 djm Exp $ */

/*
 * Copyright (c) Damien Miller 2013 <djm@mindrot.org>
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
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CHACHA_POLY_AEAD_H
#ವ್ಯಾಖ್ಯಾನಿಸು CHACHA_POLY_AEAD_H

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ "chacha.h"
#ಅನ್ತರ್ಭಾವ "poly1305.h"

#ವ್ಯಾಖ್ಯಾನಿಸು CHACHA_KEYLEN	32 /* Only 256 bit keys used here */

ರಚನೆ chachapoly_ctx;

ರಚನೆ chachapoly_ctx *chachapoly_new(ಸ್ಥಿರಾಂಕ u_char *ಕೀಲಿ, u_int keylen)
    __attribute__((__bounded__(__buffer__, 1, 2)));
ಶೂನ್ಯ chachapoly_free(ರಚನೆ chachapoly_ctx *cpctx);

ಪೂರ್ಣಾಂಕ	chachapoly_crypt(ರಚನೆ chachapoly_ctx *cpctx, u_int seqnr,
    u_char *dest, ಸ್ಥಿರಾಂಕ u_char *src, u_int len, u_int aadlen, u_int authlen,
    ಪೂರ್ಣಾಂಕ do_encrypt);
ಪೂರ್ಣಾಂಕ	chachapoly_get_ಉದ್ದಳತೆ(ರಚನೆ chachapoly_ctx *cpctx,
    u_int *plenp, u_int seqnr, ಸ್ಥಿರಾಂಕ u_char *cp, u_int len)
    __attribute__((__bounded__(__buffer__, 4, 5)));

#ಆದರೆ_ಅಂತ್ಯ /* CHACHA_POLY_AEAD_H */
