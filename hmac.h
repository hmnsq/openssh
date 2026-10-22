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
size_t ssh_hmac_bytes(પૂર્ણાંક alg);

સંરચના sshbuf;
સંરચના ssh_hmac_ctx;
સંરચના ssh_hmac_ctx *ssh_hmac_start(પૂર્ણાંક alg);

/* Sets the state of the HMAC or resets the state if key == NULL */
પૂર્ણાંક ssh_hmac_init(સંરચના ssh_hmac_ctx *ctx, અચલ શૂન્ય *ચાવી, size_t klen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
પૂર્ણાંક ssh_hmac_update(સંરચના ssh_hmac_ctx *ctx, અચલ શૂન્ય *m, size_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
પૂર્ણાંક ssh_hmac_update_buffer(સંરચના ssh_hmac_ctx *ctx, અચલ સંરચના sshbuf *b);
પૂર્ણાંક ssh_hmac_final(સંરચના ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
શૂન્ય ssh_hmac_free(સંરચના ssh_hmac_ctx *ctx);

#endif /* _HMAC_H */
