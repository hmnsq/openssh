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

#include "includes.h"

#ifndef WITH_OPENSSL

#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#如果 0
#include <md5.h>
#endif
#ifdef HAVE_SHA1_H
#include <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#include <sha2.h>
#endif

#如果 !defined(SHA256_BLOCK_LENGTH) && defined(SHA256_HMAC_BLOCK_SIZE)
#define SHA256_BLOCK_LENGTH SHA256_HMAC_BLOCK_SIZE
#endif
#如果 !defined(SHA384_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA384_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif
#如果 !defined(SHA512_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA512_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif

#include "ssherr.h"
#include "sshbuf.h"
#include "digest.h"

typedef void md_init_fn(void *mdctx);
typedef void md_update_fn(void *mdctx, const uint8_t *m, size_t mlen);
typedef void md_final_fn(uint8_t[], void *mdctx);

struct ssh_digest_ctx {
	整数 alg;
	void *mdctx;
};

struct ssh_digest {
	整数 id;
	const char *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
const struct ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		sizeof(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		sizeof(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		sizeof(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		sizeof(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		sizeof(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

static const struct ssh_digest *
ssh_digest_by_alg(整数 alg)
{
	如果 (alg < 0 || alg >= SSH_DIGEST_MAX)
		返回 NULL;
	如果 (digests[alg].id != alg) /* sanity */
		返回 NULL;
	返回 &(digests[alg]);
}

整数
ssh_digest_alg_by_name(const char *name)
{
	整数 alg;

	为 (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		如果 (strcasecmp(name, digests[alg].name) == 0)
			返回 digests[alg].id;
	}
	返回 -1;
}

const char *
ssh_digest_alg_name(整数 alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	返回 digest == NULL ? NULL : digest->name;
}

size_t
ssh_digest_bytes(整数 alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	返回 digest == NULL ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(struct ssh_digest_ctx *ctx)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	返回 digest == NULL ? 0 : digest->block_len;
}

struct ssh_digest_ctx *
ssh_digest_start(整数 alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	struct ssh_digest_ctx *ret;

	如果 (digest == NULL || (ret = calloc(1, sizeof(*ret))) == NULL)
		返回 NULL;
	如果 ((ret->mdctx = calloc(1, digest->ctx_len)) == NULL) {
		free(ret);
		返回 NULL;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	返回 ret;
}

整数
ssh_digest_copy_state(struct ssh_digest_ctx *from, struct ssh_digest_ctx *to)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(from->alg);

	如果 (digest == NULL || from->alg != to->alg)
		返回 SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	返回 0;
}

整数
ssh_digest_update(struct ssh_digest_ctx *ctx, const void *m, size_t mlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	如果 (digest == NULL)
		返回 SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	返回 0;
}

整数
ssh_digest_update_buffer(struct ssh_digest_ctx *ctx, const struct sshbuf *b)
{
	返回 ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

整数
ssh_digest_final(struct ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	如果 (digest == NULL)
		返回 SSH_ERR_INVALID_ARGUMENT;
	如果 (dlen > UINT_MAX)
		返回 SSH_ERR_INVALID_ARGUMENT;
	如果 (dlen < digest->digest_len) /* No truncation allowed */
		返回 SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	返回 0;
}

void
ssh_digest_free(struct ssh_digest_ctx *ctx)
{
	const struct ssh_digest *digest;

	如果 (ctx != NULL) {
		digest = ssh_digest_by_alg(ctx->alg);
		如果 (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			free(ctx->mdctx);
			freezero(ctx, sizeof(*ctx));
		}
	}
}

整数
ssh_digest_memory(整数 alg, const void *m, size_t mlen, u_char *d, size_t dlen)
{
	struct ssh_digest_ctx *ctx = ssh_digest_start(alg);
	整数 ret = 0;

	如果 (ctx == NULL)
		返回 SSH_ERR_INVALID_ARGUMENT;
	如果 (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	返回 ret;
}

整数
ssh_digest_buffer(整数 alg, const struct sshbuf *b, u_char *d, size_t dlen)
{
	返回 ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
