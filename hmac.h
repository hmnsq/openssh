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

#यदि_अपरिभाषितम् _HMAC_H
#परिभाषय _HMAC_H

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
आकार_t ssh_hmac_अष्टकानि(पूर्णाङ्क alg);

संरचना sshbuf;
संरचना ssh_hmac_ctx;
संरचना ssh_hmac_ctx *ssh_hmac_start(पूर्णाङ्क alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
पूर्णाङ्क ssh_hmac_init(संरचना ssh_hmac_ctx *ctx, ध्रुव शून्य *कुञ्चिका, आकार_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
पूर्णाङ्क ssh_hmac_update(संरचना ssh_hmac_ctx *ctx, ध्रुव शून्य *m, आकार_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
पूर्णाङ्क ssh_hmac_update_बफर(संरचना ssh_hmac_ctx *ctx, ध्रुव संरचना sshbuf *b);
पूर्णाङ्क ssh_hmac_final(संरचना ssh_hmac_ctx *ctx, u_char *d, आकार_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
शून्य ssh_hmac_free(संरचना ssh_hmac_ctx *ctx);

#यदि_अन्तः /* _HMAC_H */
