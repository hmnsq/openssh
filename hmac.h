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

#جے_بنا_تعریف _HMAC_H
#تعریف_کرو _HMAC_H

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
ناپ_t ssh_hmac_بائٹاں(صحيح alg);

بنية sshbuf;
بنية ssh_hmac_ctx;
بنية ssh_hmac_ctx *ssh_hmac_شروع(صحيح alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
صحيح ssh_hmac_init(بنية ssh_hmac_ctx *ctx, ثابت فراغ *کلید, ناپ_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
صحيح ssh_hmac_update(بنية ssh_hmac_ctx *ctx, ثابت فراغ *m, ناپ_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
صحيح ssh_hmac_update_بفر(بنية ssh_hmac_ctx *ctx, ثابت بنية sshbuf *b);
صحيح ssh_hmac_final(بنية ssh_hmac_ctx *ctx, u_char *d, ناپ_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
فراغ ssh_hmac_free(بنية ssh_hmac_ctx *ctx);

#جے_انت /* _HMAC_H */
