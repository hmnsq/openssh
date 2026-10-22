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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _HMAC_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _HMAC_H

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
ਮਾਪ_t ssh_hmac_ਬਾਈਟਾਂ(ਪੂਰਨ alg);

ਬਣਤਰ sshbuf;
ਬਣਤਰ ssh_hmac_ctx;
ਬਣਤਰ ssh_hmac_ctx *ssh_hmac_ਸ਼ੁਰੂ(ਪੂਰਨ alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
ਪੂਰਨ ssh_hmac_init(ਬਣਤਰ ssh_hmac_ctx *ctx, ਅਚਲ ਖਾਲੀ *ਕੁੰਜੀ, ਮਾਪ_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ਪੂਰਨ ssh_hmac_update(ਬਣਤਰ ssh_hmac_ctx *ctx, ਅਚਲ ਖਾਲੀ *m, ਮਾਪ_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ਪੂਰਨ ssh_hmac_update_ਬਫਰ(ਬਣਤਰ ssh_hmac_ctx *ctx, ਅਚਲ ਬਣਤਰ sshbuf *b);
ਪੂਰਨ ssh_hmac_final(ਬਣਤਰ ssh_hmac_ctx *ctx, u_char *d, ਮਾਪ_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ਖਾਲੀ ssh_hmac_free(ਬਣਤਰ ssh_hmac_ctx *ctx);

#ਜੇ_ਅੰਤ /* _HMAC_H */
