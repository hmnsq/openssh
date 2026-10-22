/* $OpenBSD: digest-libc.c,v 1.10 2026/03/03 09:57:25 dtucker Exp $ */
/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

#അന്തര്ഭാവ "includes.h"

#ifndef WITH_OPENSSL

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#എങ്കിൽ 0
#അന്തര്ഭാവ <md5.h>
#endif
#ifdef HAVE_SHA1_H
#അന്തര്ഭാവ <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#അന്തര്ഭാവ <sha2.h>
#endif

#എങ്കിൽ !defined(SHA256_BLOCK_LENGTH) && defined(SHA256_HMAC_BLOCK_SIZE)
#define SHA256_BLOCK_LENGTH SHA256_HMAC_BLOCK_SIZE
#endif
#എങ്കിൽ !defined(SHA384_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA384_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif
#എങ്കിൽ !defined(SHA512_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA512_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif

#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "digest.h"

തരനിർവചനം ശൂന്യം md_init_fn(ശൂന്യം *mdctx);
തരനിർവചനം ശൂന്യം md_update_fn(ശൂന്യം *mdctx, സ്ഥിരം uint8_t *m, size_t mlen);
തരനിർവചനം ശൂന്യം md_final_fn(uint8_t[], ശൂന്യം *mdctx);

ഘടന ssh_digest_ctx {
	പൂർണ്ണസംഖ്യ alg;
	ശൂന്യം *mdctx;
};

ഘടന ssh_digest {
	പൂർണ്ണസംഖ്യ id;
	സ്ഥിരം അക്ഷരം *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
സ്ഥിരം ഘടന ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		വലുപ്പം(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		വലുപ്പം(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		വലുപ്പം(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		വലുപ്പം(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		വലുപ്പം(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

സ്ഥിതം സ്ഥിരം ഘടന ssh_digest *
ssh_digest_by_alg(പൂർണ്ണസംഖ്യ alg)
{
	എങ്കിൽ (alg < 0 || alg >= SSH_DIGEST_MAX)
		തിരികെ ശൂന്യ;
	എങ്കിൽ (digests[alg].id != alg) /* sanity */
		തിരികെ ശൂന്യ;
	തിരികെ &(digests[alg]);
}

പൂർണ്ണസംഖ്യ
ssh_digest_alg_by_name(സ്ഥിരം അക്ഷരം *name)
{
	പൂർണ്ണസംഖ്യ alg;

	വേണ്ടി (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		എങ്കിൽ (strcasecmp(name, digests[alg].name) == 0)
			തിരികെ digests[alg].id;
	}
	തിരികെ -1;
}

സ്ഥിരം അക്ഷരം *
ssh_digest_alg_name(പൂർണ്ണസംഖ്യ alg)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(alg);

	തിരികെ digest == ശൂന്യ ? ശൂന്യ : digest->name;
}

size_t
ssh_digest_bytes(പൂർണ്ണസംഖ്യ alg)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(alg);

	തിരികെ digest == ശൂന്യ ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(ഘടന ssh_digest_ctx *ctx)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	തിരികെ digest == ശൂന്യ ? 0 : digest->block_len;
}

ഘടന ssh_digest_ctx *
ssh_digest_start(പൂർണ്ണസംഖ്യ alg)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(alg);
	ഘടന ssh_digest_ctx *ret;

	എങ്കിൽ (digest == ശൂന്യ || (ret = calloc(1, വലുപ്പം(*ret))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	എങ്കിൽ ((ret->mdctx = calloc(1, digest->ctx_len)) == ശൂന്യ) {
		സ്വതന്ത്രം(ret);
		തിരികെ ശൂന്യ;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
ssh_digest_copy_state(ഘടന ssh_digest_ctx *from, ഘടന ssh_digest_ctx *to)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(from->alg);

	എങ്കിൽ (digest == ശൂന്യ || from->alg != to->alg)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_digest_update(ഘടന ssh_digest_ctx *ctx, സ്ഥിരം ശൂന്യം *m, size_t mlen)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	എങ്കിൽ (digest == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_digest_update_buffer(ഘടന ssh_digest_ctx *ctx, സ്ഥിരം ഘടന sshbuf *b)
{
	തിരികെ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

പൂർണ്ണസംഖ്യ
ssh_digest_final(ഘടന ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	എങ്കിൽ (digest == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (dlen > UINT_MAX)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (dlen < digest->digest_len) /* No truncation allowed */
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	തിരികെ 0;
}

ശൂന്യം
ssh_digest_free(ഘടന ssh_digest_ctx *ctx)
{
	സ്ഥിരം ഘടന ssh_digest *digest;

	എങ്കിൽ (ctx != ശൂന്യ) {
		digest = ssh_digest_by_alg(ctx->alg);
		എങ്കിൽ (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			സ്വതന്ത്രം(ctx->mdctx);
			freezero(ctx, വലുപ്പം(*ctx));
		}
	}
}

പൂർണ്ണസംഖ്യ
ssh_digest_memory(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം ശൂന്യം *m, size_t mlen, u_char *d, size_t dlen)
{
	ഘടന ssh_digest_ctx *ctx = ssh_digest_start(alg);
	പൂർണ്ണസംഖ്യ ret = 0;

	എങ്കിൽ (ctx == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
ssh_digest_buffer(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം ഘടന sshbuf *b, u_char *d, size_t dlen)
{
	തിരികെ ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
