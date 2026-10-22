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

#اگر_غیر_تعریف_شدہ _HMAC_H
#تعریف_کرو _HMAC_H

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
سائز_t ssh_hmac_بائٹیں(صحیح alg);

ساخت sshbuf;
ساخت ssh_hmac_ctx;
ساخت ssh_hmac_ctx *ssh_hmac_آغاز(صحیح alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
صحیح ssh_hmac_init(ساخت ssh_hmac_ctx *ctx, ثابت خالی *کلید, سائز_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
صحیح ssh_hmac_update(ساخت ssh_hmac_ctx *ctx, ثابت خالی *m, سائز_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
صحیح ssh_hmac_update_بفر(ساخت ssh_hmac_ctx *ctx, ثابت ساخت sshbuf *b);
صحیح ssh_hmac_final(ساخت ssh_hmac_ctx *ctx, u_char *d, سائز_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
خالی ssh_hmac_free(ساخت ssh_hmac_ctx *ctx);

#اگر_ختم /* _HMAC_H */
