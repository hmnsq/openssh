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
	цео alg;
	EVP_MD_CTX *mdctx;
};

struct ssh_digest {
	цео id;
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
ssh_digest_by_alg(цео alg)
{
	ако (alg < 0 || alg >= SSH_DIGEST_MAX)
		врати NULL;
	ако (digests[alg].id != alg) /* sanity */
		врати NULL;
	ако (digests[alg].mdfunc == NULL)
		врати NULL;
	врати &(digests[alg]);
}

цео
ssh_digest_alg_by_name(const char *name)
{
	цео alg;

	за (alg = 0; digests[alg].id != -1; alg++) {
		ако (strcasecmp(name, digests[alg].name) == 0)
			врати digests[alg].id;
	}
	врати -1;
}

const char *
ssh_digest_alg_name(цео alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	врати digest == NULL ? NULL : digest->name;
}

size_t
ssh_digest_bytes(цео alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	врати digest == NULL ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(struct ssh_digest_ctx *ctx)
{
	врати EVP_MD_CTX_block_size(ctx->mdctx);
}

struct ssh_digest_ctx *
ssh_digest_start(цео alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	struct ssh_digest_ctx *ret;

	ако (digest == NULL || ((ret = calloc(1, sizeof(*ret))) == NULL))
		врати NULL;
	ret->alg = alg;
	ако ((ret->mdctx = EVP_MD_CTX_new()) == NULL) {
		free(ret);
		врати NULL;
	}
	ако (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), NULL) != 1) {
		ssh_digest_free(ret);
		врати NULL;
	}
	врати ret;
}

цео
ssh_digest_copy_state(struct ssh_digest_ctx *from, struct ssh_digest_ctx *to)
{
	ако (from->alg != to->alg)
		врати SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	ако (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		врати SSH_ERR_LIBCRYPTO_ERROR;
	врати 0;
}

цео
ssh_digest_update(struct ssh_digest_ctx *ctx, const void *m, size_t mlen)
{
	ако (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		врати SSH_ERR_LIBCRYPTO_ERROR;
	врати 0;
}

цео
ssh_digest_update_buffer(struct ssh_digest_ctx *ctx, const struct sshbuf *b)
{
	врати ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

цео
ssh_digest_final(struct ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	ако (digest == NULL || dlen > UINT_MAX)
		врати SSH_ERR_INVALID_ARGUMENT;
	ако (dlen < digest->digest_len) /* No truncation allowed */
		врати SSH_ERR_INVALID_ARGUMENT;
	ако (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		врати SSH_ERR_LIBCRYPTO_ERROR;
	ако (l != digest->digest_len) /* sanity */
		врати SSH_ERR_INTERNAL_ERROR;
	врати 0;
}

void
ssh_digest_free(struct ssh_digest_ctx *ctx)
{
	ако (ctx == NULL)
		врати;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, sizeof(*ctx));
}

цео
ssh_digest_memory(цео alg, const void *m, size_t mlen, u_char *d, size_t dlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	ако (digest == NULL)
		врати SSH_ERR_INVALID_ARGUMENT;
	ако (dlen > UINT_MAX)
		врати SSH_ERR_INVALID_ARGUMENT;
	ако (dlen < digest->digest_len)
		врати SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	ако (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), NULL))
		врати SSH_ERR_LIBCRYPTO_ERROR;
	врати 0;
}

цео
ssh_digest_buffer(цео alg, const struct sshbuf *b, u_char *d, size_t dlen)
{
	врати ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
