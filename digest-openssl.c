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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

#ifndef HAVE_EVP_SHA256
# define EVP_sha256 ರಿಕ್ತ
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 ರಿಕ್ತ
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 ರಿಕ್ತ
#endif

ಸಂರಚನಾ ssh_digest_ctx {
	ಪೂರ್ಣಾಙ್ಕ alg;
	EVP_MD_CTX *mdctx;
};

ಸಂರಚನಾ ssh_digest {
	ಪೂರ್ಣಾಙ್ಕ id;
	ಧ್ರುವ ವರ್ಣ *name;
	size_t digest_len;
	ಧ್ರುವ EVP_MD *(*mdfunc)(ಶೂನ್ಯ);
};

/* NB. Indexed directly by algorithm number */
ಧ್ರುವ ಸಂರಚನಾ ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			ರಿಕ್ತ,		0,	ರಿಕ್ತ },
};

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ ssh_digest *
ssh_digest_by_alg(ಪೂರ್ಣಾಙ್ಕ alg)
{
	ಯದಿ (alg < 0 || alg >= SSH_DIGEST_MAX)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ (digests[alg].id != alg) /* sanity */
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ (digests[alg].mdfunc == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ &(digests[alg]);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_alg_by_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪೂರ್ಣಾಙ್ಕ alg;

	ಪ್ರತಿ (alg = 0; digests[alg].id != -1; alg++) {
		ಯದಿ (strcasecmp(name, digests[alg].name) == 0)
			ಪ್ರತ್ಯಾಗಮ digests[alg].id;
	}
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಧ್ರುವ ವರ್ಣ *
ssh_digest_alg_name(ಪೂರ್ಣಾಙ್ಕ alg)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(alg);

	ಪ್ರತ್ಯಾಗಮ digest == ರಿಕ್ತ ? ರಿಕ್ತ : digest->name;
}

size_t
ssh_digest_bytes(ಪೂರ್ಣಾಙ್ಕ alg)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(alg);

	ಪ್ರತ್ಯಾಗಮ digest == ರಿಕ್ತ ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(ಸಂರಚನಾ ssh_digest_ctx *ctx)
{
	ಪ್ರತ್ಯಾಗಮ EVP_MD_CTX_block_size(ctx->mdctx);
}

ಸಂರಚನಾ ssh_digest_ctx *
ssh_digest_start(ಪೂರ್ಣಾಙ್ಕ alg)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(alg);
	ಸಂರಚನಾ ssh_digest_ctx *ret;

	ಯದಿ (digest == ರಿಕ್ತ || ((ret = calloc(1, ಪರಿಮಾಣ(*ret))) == ರಿಕ್ತ))
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ret->alg = alg;
	ಯದಿ ((ret->mdctx = EVP_MD_CTX_new()) == ರಿಕ್ತ) {
		ಮುಕ್ತ(ret);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), ರಿಕ್ತ) != 1) {
		ssh_digest_free(ret);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_copy_state(ಸಂರಚನಾ ssh_digest_ctx *from, ಸಂರಚನಾ ssh_digest_ctx *to)
{
	ಯದಿ (from->alg != to->alg)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	ಯದಿ (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_update(ಸಂರಚನಾ ssh_digest_ctx *ctx, ಧ್ರುವ ಶೂನ್ಯ *m, size_t mlen)
{
	ಯದಿ (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_update_buffer(ಸಂರಚನಾ ssh_digest_ctx *ctx, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b)
{
	ಪ್ರತ್ಯಾಗಮ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_final(ಸಂರಚನಾ ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	ಯದಿ (digest == ರಿಕ್ತ || dlen > UINT_MAX)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (dlen < digest->digest_len) /* No truncation allowed */
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	ಯದಿ (l != digest->digest_len) /* sanity */
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
ssh_digest_free(ಸಂರಚನಾ ssh_digest_ctx *ctx)
{
	ಯದಿ (ctx == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, ಪರಿಮಾಣ(*ctx));
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_memory(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ ಶೂನ್ಯ *m, size_t mlen, u_char *d, size_t dlen)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	ಯದಿ (digest == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (dlen > UINT_MAX)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (dlen < digest->digest_len)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	ಯದಿ (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), ರಿಕ್ತ))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_buffer(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b, u_char *d, size_t dlen)
{
	ಪ್ರತ್ಯಾಗಮ ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
