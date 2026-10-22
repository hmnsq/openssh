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
size_t ssh_hmac_bytes(ಪೂರ್ಣಾಙ್ಕ alg);

ಸಂರಚನಾ sshbuf;
ಸಂರಚನಾ ssh_hmac_ctx;
ಸಂರಚನಾ ssh_hmac_ctx *ssh_hmac_start(ಪೂರ್ಣಾಙ್ಕ alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
ಪೂರ್ಣಾಙ್ಕ ssh_hmac_init(ಸಂರಚನಾ ssh_hmac_ctx *ctx, ಧ್ರುವ ಶೂನ್ಯ *ಕೀಲಿ, size_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ಪೂರ್ಣಾಙ್ಕ ssh_hmac_update(ಸಂರಚನಾ ssh_hmac_ctx *ctx, ಧ್ರುವ ಶೂನ್ಯ *m, size_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ಪೂರ್ಣಾಙ್ಕ ssh_hmac_update_buffer(ಸಂರಚನಾ ssh_hmac_ctx *ctx, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b);
ಪೂರ್ಣಾಙ್ಕ ssh_hmac_final(ಸಂರಚನಾ ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ಶೂನ್ಯ ssh_hmac_free(ಸಂರಚನಾ ssh_hmac_ctx *ctx);

#endif /* _HMAC_H */
