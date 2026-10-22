/* $OpenBSD: digest.h,v 1.8 2017/05/08 22:57:38 djm Exp $ */
/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

#ifndef _DIGEST_H
#define _DIGEST_H

/* Maximum digest output length */
#define SSH_DIGEST_MAX_LENGTH	64

/* Digest algorithms */
#define SSH_DIGEST_MD5		0
#define SSH_DIGEST_SHA1		1
#define SSH_DIGEST_SHA256	2
#define SSH_DIGEST_SHA384	3
#define SSH_DIGEST_SHA512	4
#define SSH_DIGEST_MAX		5

ഘടന sshbuf;
ഘടന ssh_digest_ctx;

/* Looks up a digest algorithm by name */
പൂർണ്ണസംഖ്യ ssh_digest_alg_by_name(സ്ഥിരം അക്ഷരം *name);

/* Returns the algorithm name for a digest identifier */
സ്ഥിരം അക്ഷരം *ssh_digest_alg_name(പൂർണ്ണസംഖ്യ alg);

/* Returns the algorithm's digest length in bytes or 0 for invalid algorithm */
size_t ssh_digest_bytes(പൂർണ്ണസംഖ്യ alg);

/* Returns the block size of the digest, e.g. for implementing HMAC */
size_t ssh_digest_blocksize(ഘടന ssh_digest_ctx *ctx);

/* Copies internal state of digest of 'from' to 'to' */
പൂർണ്ണസംഖ്യ ssh_digest_copy_state(ഘടന ssh_digest_ctx *from,
    ഘടന ssh_digest_ctx *to);

/* One-shot API */
പൂർണ്ണസംഖ്യ ssh_digest_memory(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം ശൂന്യം *m, size_t mlen,
    u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)))
	__attribute__((__bounded__(__buffer__, 4, 5)));
പൂർണ്ണസംഖ്യ ssh_digest_buffer(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം ഘടന sshbuf *b, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 3, 4)));

/* Update API */
ഘടന ssh_digest_ctx *ssh_digest_start(പൂർണ്ണസംഖ്യ alg);
പൂർണ്ണസംഖ്യ ssh_digest_update(ഘടന ssh_digest_ctx *ctx, സ്ഥിരം ശൂന്യം *m, size_t mlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
പൂർണ്ണസംഖ്യ ssh_digest_update_buffer(ഘടന ssh_digest_ctx *ctx,
    സ്ഥിരം ഘടന sshbuf *b);
പൂർണ്ണസംഖ്യ ssh_digest_final(ഘടന ssh_digest_ctx *ctx, u_char *d, size_t dlen)
	__attribute__((__bounded__(__buffer__, 2, 3)));
ശൂന്യം ssh_digest_free(ഘടന ssh_digest_ctx *ctx);

#endif /* _DIGEST_H */

