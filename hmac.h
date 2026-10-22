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

#ifndef _HMAC_H
#define _HMAC_H

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
size_t ssh_hmac_bytes(صحیح alg);

ساختار sshbuf;
ساختار ssh_hmac_ctx;
ساختار ssh_hmac_ctx *ssh_hmac_start(صحیح alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
صحیح ssh_hmac_init(ساختار ssh_hmac_ctx *ctx, ثابت تهی *کلید, size_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
صحیح ssh_hmac_update(ساختار ssh_hmac_ctx *ctx, ثابت تهی *m, size_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
صحیح ssh_hmac_update_buffer(ساختار ssh_hmac_ctx *ctx, ثابت ساختار sshbuf *b);
صحیح ssh_hmac_final(ساختار ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
تهی ssh_hmac_free(ساختار ssh_hmac_ctx *ctx);

#endif /* _HMAC_H */
