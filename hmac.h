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
size_t ssh_hmac_bytes(পূর্ণাঙ্ক alg);

সংরচনা sshbuf;
সংরচনা ssh_hmac_ctx;
সংরচনা ssh_hmac_ctx *ssh_hmac_start(পূর্ণাঙ্ক alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
পূর্ণাঙ্ক ssh_hmac_init(সংরচনা ssh_hmac_ctx *ctx, ধ্রুৱ শূন্য *চাবি, size_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
পূর্ণাঙ্ক ssh_hmac_update(সংরচনা ssh_hmac_ctx *ctx, ধ্রুৱ শূন্য *m, size_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
পূর্ণাঙ্ক ssh_hmac_update_buffer(সংরচনা ssh_hmac_ctx *ctx, ধ্রুৱ সংরচনা sshbuf *b);
পূর্ণাঙ্ক ssh_hmac_final(সংরচনা ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
শূন্য ssh_hmac_free(সংরচনা ssh_hmac_ctx *ctx);

#endif /* _HMAC_H */
