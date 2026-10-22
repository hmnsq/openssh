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
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CHACHA_POLY_AEAD_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHACHA_POLY_AEAD_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "chacha.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "poly1305.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHACHA_KEYLEN	32 /* Only 256 bit keys used here */

ਬਣਤਰ chachapoly_ctx;

ਬਣਤਰ chachapoly_ctx *chachapoly_new(ਅਚਲ u_char *ਕੁੰਜੀ, u_int keylen)
    __attribute__((__bounded__(__buffer__, 1, 2)));
ਖਾਲੀ chachapoly_free(ਬਣਤਰ chachapoly_ctx *cpctx);

ਪੂਰਨ	chachapoly_crypt(ਬਣਤਰ chachapoly_ctx *cpctx, u_int seqnr,
    u_char *dest, ਅਚਲ u_char *src, u_int len, u_int aadlen, u_int authlen,
    ਪੂਰਨ do_encrypt);
ਪੂਰਨ	chachapoly_get_ਲੰਮਾਈ(ਬਣਤਰ chachapoly_ctx *cpctx,
    u_int *plenp, u_int seqnr, ਅਚਲ u_char *cp, u_int len)
    __attribute__((__bounded__(__buffer__, 4, 5)));

#ਜੇ_ਅੰਤ /* CHACHA_POLY_AEAD_H */
