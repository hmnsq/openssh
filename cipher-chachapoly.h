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

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव "chacha.h"
#अन्तर्भाव "poly1305.h"

#define CHACHA_KEYLEN	32 /* Only 256 bit keys used here */

संरचना chachapoly_ctx;

संरचना chachapoly_ctx *chachapoly_new(स्थिरांक u_char *किल्ली, u_int keylen)
    __attribute__((__bounded__(__buffer__, 1, 2)));
शून्य chachapoly_free(संरचना chachapoly_ctx *cpctx);

पूर्णांक	chachapoly_crypt(संरचना chachapoly_ctx *cpctx, u_int seqnr,
    u_char *dest, स्थिरांक u_char *src, u_int len, u_int aadlen, u_int authlen,
    पूर्णांक do_encrypt);
पूर्णांक	chachapoly_get_length(संरचना chachapoly_ctx *cpctx,
    u_int *plenp, u_int seqnr, स्थिरांक u_char *cp, u_int len)
    __attribute__((__bounded__(__buffer__, 4, 5)));

#endif /* CHACHA_POLY_AEAD_H */
