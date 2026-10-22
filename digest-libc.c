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

#ຖ້າ 0
#include <md5.h>
#endif
#ifdef HAVE_SHA1_H
#include <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#include <sha2.h>
#endif

#ຖ້າ !defined(SHA256_BLOCK_LENGTH) && defined(SHA256_HMAC_BLOCK_SIZE)
#define SHA256_BLOCK_LENGTH SHA256_HMAC_BLOCK_SIZE
#endif
#ຖ້າ !defined(SHA384_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA384_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif
#ຖ້າ !defined(SHA512_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA512_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif

#include "ssherr.h"
#include "sshbuf.h"
#include "digest.h"

typedef void md_init_fn(void *mdctx);
typedef void md_update_fn(void *mdctx, const uint8_t *m, size_t mlen);
typedef void md_final_fn(uint8_t[], void *mdctx);

sa_nracanaa ssh_digest_ctx {
	ຈຳນວນເຕັມ alg;
	void *mdctx;
};

sa_nracanaa ssh_digest {
	ຈຳນວນເຕັມ id;
	const var_na *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
const sa_nracanaa ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		parimaa_na(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		parimaa_na(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		parimaa_na(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		parimaa_na(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		parimaa_na(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

static const sa_nracanaa ssh_digest *
ssh_digest_by_alg(ຈຳນວນເຕັມ alg)
{
	ຖ້າ (alg < 0 || alg >= SSH_DIGEST_MAX)
		ສົ່ງຄືນ NULL;
	ຖ້າ (digests[alg].id != alg) /* sanity */
		ສົ່ງຄືນ NULL;
	ສົ່ງຄືນ &(digests[alg]);
}

ຈຳນວນເຕັມ
ssh_digest_alg_by_name(const var_na *name)
{
	ຈຳນວນເຕັມ alg;

	ສຳລັບ (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		ຖ້າ (strcasecmp(name, digests[alg].name) == 0)
			ສົ່ງຄືນ digests[alg].id;
	}
	ສົ່ງຄືນ -1;
}

const var_na *
ssh_digest_alg_name(ຈຳນວນເຕັມ alg)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(alg);

	ສົ່ງຄືນ digest == NULL ? NULL : digest->name;
}

size_t
ssh_digest_bytes(ຈຳນວນເຕັມ alg)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(alg);

	ສົ່ງຄືນ digest == NULL ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(sa_nracanaa ssh_digest_ctx *ctx)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ສົ່ງຄືນ digest == NULL ? 0 : digest->block_len;
}

sa_nracanaa ssh_digest_ctx *
ssh_digest_start(ຈຳນວນເຕັມ alg)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(alg);
	sa_nracanaa ssh_digest_ctx *ret;

	ຖ້າ (digest == NULL || (ret = calloc(1, parimaa_na(*ret))) == NULL)
		ສົ່ງຄືນ NULL;
	ຖ້າ ((ret->mdctx = calloc(1, digest->ctx_len)) == NULL) {
		free(ret);
		ສົ່ງຄືນ NULL;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	ສົ່ງຄືນ ret;
}

ຈຳນວນເຕັມ
ssh_digest_copy_state(sa_nracanaa ssh_digest_ctx *from, sa_nracanaa ssh_digest_ctx *to)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(from->alg);

	ຖ້າ (digest == NULL || from->alg != to->alg)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
ssh_digest_update(sa_nracanaa ssh_digest_ctx *ctx, const void *m, size_t mlen)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ຖ້າ (digest == NULL)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
ssh_digest_update_buffer(sa_nracanaa ssh_digest_ctx *ctx, const sa_nracanaa sshbuf *b)
{
	ສົ່ງຄືນ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

ຈຳນວນເຕັມ
ssh_digest_final(sa_nracanaa ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ຖ້າ (digest == NULL)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	ຖ້າ (dlen > UINT_MAX)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	ຖ້າ (dlen < digest->digest_len) /* No truncation allowed */
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	ສົ່ງຄືນ 0;
}

void
ssh_digest_free(sa_nracanaa ssh_digest_ctx *ctx)
{
	const sa_nracanaa ssh_digest *digest;

	ຖ້າ (ctx != NULL) {
		digest = ssh_digest_by_alg(ctx->alg);
		ຖ້າ (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			free(ctx->mdctx);
			freezero(ctx, parimaa_na(*ctx));
		}
	}
}

ຈຳນວນເຕັມ
ssh_digest_memory(ຈຳນວນເຕັມ alg, const void *m, size_t mlen, u_char *d, size_t dlen)
{
	sa_nracanaa ssh_digest_ctx *ctx = ssh_digest_start(alg);
	ຈຳນວນເຕັມ ret = 0;

	ຖ້າ (ctx == NULL)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	ຖ້າ (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	ສົ່ງຄືນ ret;
}

ຈຳນວນເຕັມ
ssh_digest_buffer(ຈຳນວນເຕັມ alg, const sa_nracanaa sshbuf *b, u_char *d, size_t dlen)
{
	ສົ່ງຄືນ ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
