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

sa_nracanaa ssh_digest_ctx {
	ཧྲིལ alg;
	EVP_MD_CTX *mdctx;
};

sa_nracanaa ssh_digest {
	ཧྲིལ id;
	const var_na *name;
	size_t digest_len;
	const EVP_MD *(*mdfunc)(void);
};

/* NB. Indexed directly by algorithm number */
const sa_nracanaa ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			NULL,		0,	NULL },
};

static const sa_nracanaa ssh_digest *
ssh_digest_by_alg(ཧྲིལ alg)
{
	གལ་སྲིད (alg < 0 || alg >= SSH_DIGEST_MAX)
		ལོག NULL;
	གལ་སྲིད (digests[alg].id != alg) /* sanity */
		ལོག NULL;
	གལ་སྲིད (digests[alg].mdfunc == NULL)
		ལོག NULL;
	ལོག &(digests[alg]);
}

ཧྲིལ
ssh_digest_alg_by_name(const var_na *name)
{
	ཧྲིལ alg;

	དོན་ལུ (alg = 0; digests[alg].id != -1; alg++) {
		གལ་སྲིད (strcasecmp(name, digests[alg].name) == 0)
			ལོག digests[alg].id;
	}
	ལོག -1;
}

const var_na *
ssh_digest_alg_name(ཧྲིལ alg)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(alg);

	ལོག digest == NULL ? NULL : digest->name;
}

size_t
ssh_digest_bytes(ཧྲིལ alg)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(alg);

	ལོག digest == NULL ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(sa_nracanaa ssh_digest_ctx *ctx)
{
	ལོག EVP_MD_CTX_block_size(ctx->mdctx);
}

sa_nracanaa ssh_digest_ctx *
ssh_digest_start(ཧྲིལ alg)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(alg);
	sa_nracanaa ssh_digest_ctx *ret;

	གལ་སྲིད (digest == NULL || ((ret = calloc(1, parimaa_na(*ret))) == NULL))
		ལོག NULL;
	ret->alg = alg;
	གལ་སྲིད ((ret->mdctx = EVP_MD_CTX_new()) == NULL) {
		free(ret);
		ལོག NULL;
	}
	གལ་སྲིད (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), NULL) != 1) {
		ssh_digest_free(ret);
		ལོག NULL;
	}
	ལོག ret;
}

ཧྲིལ
ssh_digest_copy_state(sa_nracanaa ssh_digest_ctx *from, sa_nracanaa ssh_digest_ctx *to)
{
	གལ་སྲིད (from->alg != to->alg)
		ལོག SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	གལ་སྲིད (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		ལོག SSH_ERR_LIBCRYPTO_ERROR;
	ལོག 0;
}

ཧྲིལ
ssh_digest_update(sa_nracanaa ssh_digest_ctx *ctx, const void *m, size_t mlen)
{
	གལ་སྲིད (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		ལོག SSH_ERR_LIBCRYPTO_ERROR;
	ལོག 0;
}

ཧྲིལ
ssh_digest_update_buffer(sa_nracanaa ssh_digest_ctx *ctx, const sa_nracanaa sshbuf *b)
{
	ལོག ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

ཧྲིལ
ssh_digest_final(sa_nracanaa ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	གལ་སྲིད (digest == NULL || dlen > UINT_MAX)
		ལོག SSH_ERR_INVALID_ARGUMENT;
	གལ་སྲིད (dlen < digest->digest_len) /* No truncation allowed */
		ལོག SSH_ERR_INVALID_ARGUMENT;
	གལ་སྲིད (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		ལོག SSH_ERR_LIBCRYPTO_ERROR;
	གལ་སྲིད (l != digest->digest_len) /* sanity */
		ལོག SSH_ERR_INTERNAL_ERROR;
	ལོག 0;
}

void
ssh_digest_free(sa_nracanaa ssh_digest_ctx *ctx)
{
	གལ་སྲིད (ctx == NULL)
		ལོག;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, parimaa_na(*ctx));
}

ཧྲིལ
ssh_digest_memory(ཧྲིལ alg, const void *m, size_t mlen, u_char *d, size_t dlen)
{
	const sa_nracanaa ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	གལ་སྲིད (digest == NULL)
		ལོག SSH_ERR_INVALID_ARGUMENT;
	གལ་སྲིད (dlen > UINT_MAX)
		ལོག SSH_ERR_INVALID_ARGUMENT;
	གལ་སྲིད (dlen < digest->digest_len)
		ལོག SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	གལ་སྲིད (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), NULL))
		ལོག SSH_ERR_LIBCRYPTO_ERROR;
	ལོག 0;
}

ཧྲིལ
ssh_digest_buffer(ཧྲིལ alg, const sa_nracanaa sshbuf *b, u_char *d, size_t dlen)
{
	ལོག ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
