/* $OpenBSD: digest-openssl.c,v 1.9 2020/10/29 02:52:43 djm Exp $ */
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

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "openbsd-compat/openssl-compat.h"

#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

#ifndef HAVE_EVP_SHA256
# define EVP_sha256 NULL
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 NULL
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 NULL
#endif

struct ssh_digest_ctx {
	整数 alg;
	EVP_MD_CTX *mdctx;
};

struct ssh_digest {
	整数 id;
	const char *name;
	size_t digest_len;
	const EVP_MD *(*mdfunc)(void);
};

/* NB. Indexed directly by algorithm number */
const struct ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			NULL,		0,	NULL },
};

static const struct ssh_digest *
ssh_digest_by_alg(整数 alg)
{
	もし (alg < 0 || alg >= SSH_DIGEST_MAX)
		戻る NULL;
	もし (digests[alg].id != alg) /* sanity */
		戻る NULL;
	もし (digests[alg].mdfunc == NULL)
		戻る NULL;
	戻る &(digests[alg]);
}

整数
ssh_digest_alg_by_name(const char *name)
{
	整数 alg;

	ために (alg = 0; digests[alg].id != -1; alg++) {
		もし (strcasecmp(name, digests[alg].name) == 0)
			戻る digests[alg].id;
	}
	戻る -1;
}

const char *
ssh_digest_alg_name(整数 alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	戻る digest == NULL ? NULL : digest->name;
}

size_t
ssh_digest_bytes(整数 alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	戻る digest == NULL ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(struct ssh_digest_ctx *ctx)
{
	戻る EVP_MD_CTX_block_size(ctx->mdctx);
}

struct ssh_digest_ctx *
ssh_digest_start(整数 alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	struct ssh_digest_ctx *ret;

	もし (digest == NULL || ((ret = calloc(1, sizeof(*ret))) == NULL))
		戻る NULL;
	ret->alg = alg;
	もし ((ret->mdctx = EVP_MD_CTX_new()) == NULL) {
		free(ret);
		戻る NULL;
	}
	もし (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), NULL) != 1) {
		ssh_digest_free(ret);
		戻る NULL;
	}
	戻る ret;
}

整数
ssh_digest_copy_state(struct ssh_digest_ctx *from, struct ssh_digest_ctx *to)
{
	もし (from->alg != to->alg)
		戻る SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	もし (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		戻る SSH_ERR_LIBCRYPTO_ERROR;
	戻る 0;
}

整数
ssh_digest_update(struct ssh_digest_ctx *ctx, const void *m, size_t mlen)
{
	もし (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		戻る SSH_ERR_LIBCRYPTO_ERROR;
	戻る 0;
}

整数
ssh_digest_update_buffer(struct ssh_digest_ctx *ctx, const struct sshbuf *b)
{
	戻る ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

整数
ssh_digest_final(struct ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	もし (digest == NULL || dlen > UINT_MAX)
		戻る SSH_ERR_INVALID_ARGUMENT;
	もし (dlen < digest->digest_len) /* No truncation allowed */
		戻る SSH_ERR_INVALID_ARGUMENT;
	もし (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		戻る SSH_ERR_LIBCRYPTO_ERROR;
	もし (l != digest->digest_len) /* sanity */
		戻る SSH_ERR_INTERNAL_ERROR;
	戻る 0;
}

void
ssh_digest_free(struct ssh_digest_ctx *ctx)
{
	もし (ctx == NULL)
		戻る;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, sizeof(*ctx));
}

整数
ssh_digest_memory(整数 alg, const void *m, size_t mlen, u_char *d, size_t dlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	もし (digest == NULL)
		戻る SSH_ERR_INVALID_ARGUMENT;
	もし (dlen > UINT_MAX)
		戻る SSH_ERR_INVALID_ARGUMENT;
	もし (dlen < digest->digest_len)
		戻る SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	もし (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), NULL))
		戻る SSH_ERR_LIBCRYPTO_ERROR;
	戻る 0;
}

整数
ssh_digest_buffer(整数 alg, const struct sshbuf *b, u_char *d, size_t dlen)
{
	戻る ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
