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
#ifndef CHACHA_POLY_AEAD_H
#define CHACHA_POLY_AEAD_H

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ "chacha.h"
#அந்தர்பாவ "poly1305.h"

#define CHACHA_KEYLEN	32 /* Only 256 bit keys used here */

கட்டமைப்பு chachapoly_ctx;

கட்டமைப்பு chachapoly_ctx *chachapoly_new(மாறிலி u_char *சாவி, u_int keylen)
    __attribute__((__bounded__(__buffer__, 1, 2)));
வெறுமை chachapoly_free(கட்டமைப்பு chachapoly_ctx *cpctx);

முழு	chachapoly_crypt(கட்டமைப்பு chachapoly_ctx *cpctx, u_int seqnr,
    u_char *dest, மாறிலி u_char *src, u_int len, u_int aadlen, u_int authlen,
    முழு do_encrypt);
முழு	chachapoly_get_length(கட்டமைப்பு chachapoly_ctx *cpctx,
    u_int *plenp, u_int seqnr, மாறிலி u_char *cp, u_int len)
    __attribute__((__bounded__(__buffer__, 4, 5)));

#endif /* CHACHA_POLY_AEAD_H */
