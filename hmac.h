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

#अगर_अघोषित _HMAC_H
#घोषणा _HMAC_H

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
माप_प्रकार ssh_hmac_bytes(पूर्णांक alg);

काष्ठा sshbuf;
काष्ठा ssh_hmac_ctx;
काष्ठा ssh_hmac_ctx *ssh_hmac_start(पूर्णांक alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
पूर्णांक ssh_hmac_init(काष्ठा ssh_hmac_ctx *ctx, स्थिर व्योम *कुंजी, माप_प्रकार klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
पूर्णांक ssh_hmac_update(काष्ठा ssh_hmac_ctx *ctx, स्थिर व्योम *m, माप_प्रकार mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
पूर्णांक ssh_hmac_update_बफर(काष्ठा ssh_hmac_ctx *ctx, स्थिर काष्ठा sshbuf *b);
पूर्णांक ssh_hmac_final(काष्ठा ssh_hmac_ctx *ctx, u_char *d, माप_प्रकार dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
व्योम ssh_hmac_free(काष्ठा ssh_hmac_ctx *ctx);

#पूर्ण_अगर /* _HMAC_H */
