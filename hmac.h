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
আকার_t ssh_hmac_bytes(পূর্ণসংখ্যা alg);

কাঠামো sshbuf;
কাঠামো ssh_hmac_ctx;
কাঠামো ssh_hmac_ctx *ssh_hmac_start(পূর্ণসংখ্যা alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
পূর্ণসংখ্যা ssh_hmac_init(কাঠামো ssh_hmac_ctx *ctx, ধ্রুবক শূন্য *চাবি, আকার_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
পূর্ণসংখ্যা ssh_hmac_update(কাঠামো ssh_hmac_ctx *ctx, ধ্রুবক শূন্য *m, আকার_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
পূর্ণসংখ্যা ssh_hmac_update_বাফার(কাঠামো ssh_hmac_ctx *ctx, ধ্রুবক কাঠামো sshbuf *b);
পূর্ণসংখ্যা ssh_hmac_final(কাঠামো ssh_hmac_ctx *ctx, u_char *d, আকার_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
শূন্য ssh_hmac_free(কাঠামো ssh_hmac_ctx *ctx);

#endif /* _HMAC_H */
