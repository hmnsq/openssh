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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_SHA256
# define EVP_sha256 ਨਿਰਾ
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_SHA384
# define EVP_sha384 ਨਿਰਾ
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_SHA512
# define EVP_sha512 ਨਿਰਾ
#ਜੇ_ਅੰਤ

ਬਣਤਰ ssh_digest_ctx {
	ਪੂਰਨ alg;
	EVP_MD_CTX *mdctx;
};

ਬਣਤਰ ssh_digest {
	ਪੂਰਨ id;
	ਅਚਲ ਅੱਖਰ *name;
	ਮਾਪ_t digest_len;
	ਅਚਲ EVP_MD *(*mdfunc)(ਖਾਲੀ);
};

/* NB. Indexed directly by algorithm number */
ਅਚਲ ਬਣਤਰ ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			ਨਿਰਾ,		0,	ਨਿਰਾ },
};

ਸਥਿਰ ਅਚਲ ਬਣਤਰ ssh_digest *
ssh_digest_by_alg(ਪੂਰਨ alg)
{
	ਜੇ (alg < 0 || alg >= SSH_DIGEST_MAX)
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ (digests[alg].id != alg) /* sanity */
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ (digests[alg].mdfunc == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਵਾਪਸ &(digests[alg]);
}

ਪੂਰਨ
ssh_digest_alg_by_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਪੂਰਨ alg;

	ਲਈ (alg = 0; digests[alg].id != -1; alg++) {
		ਜੇ (strcasecmp(name, digests[alg].name) == 0)
			ਵਾਪਸ digests[alg].id;
	}
	ਵਾਪਸ -1;
}

ਅਚਲ ਅੱਖਰ *
ssh_digest_alg_name(ਪੂਰਨ alg)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(alg);

	ਵਾਪਸ digest == ਨਿਰਾ ? ਨਿਰਾ : digest->name;
}

ਮਾਪ_t
ssh_digest_ਬਾਈਟਾਂ(ਪੂਰਨ alg)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(alg);

	ਵਾਪਸ digest == ਨਿਰਾ ? 0 : digest->digest_len;
}

ਮਾਪ_t
ssh_digest_blocksize(ਬਣਤਰ ssh_digest_ctx *ctx)
{
	ਵਾਪਸ EVP_MD_CTX_ਖੰਡ_ਮਾਪ(ctx->mdctx);
}

ਬਣਤਰ ssh_digest_ctx *
ssh_digest_ਸ਼ੁਰੂ(ਪੂਰਨ alg)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(alg);
	ਬਣਤਰ ssh_digest_ctx *ret;

	ਜੇ (digest == ਨਿਰਾ || ((ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret))) == ਨਿਰਾ))
		ਵਾਪਸ ਨਿਰਾ;
	ret->alg = alg;
	ਜੇ ((ret->mdctx = EVP_MD_CTX_new()) == ਨਿਰਾ) {
		ਮੁਕਤ(ret);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), ਨਿਰਾ) != 1) {
		ssh_digest_free(ret);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ ret;
}

ਪੂਰਨ
ssh_digest_copy_state(ਬਣਤਰ ssh_digest_ctx *from, ਬਣਤਰ ssh_digest_ctx *ਮੰਜ਼ਿਲ)
{
	ਜੇ (from->alg != ਮੰਜ਼ਿਲ->alg)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	/* we have bcopy-style order while openssl has memcpy-style */
	ਜੇ (!EVP_MD_CTX_copy_ex(ਮੰਜ਼ਿਲ->mdctx, from->mdctx))
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_digest_update(ਬਣਤਰ ssh_digest_ctx *ctx, ਅਚਲ ਖਾਲੀ *m, ਮਾਪ_t mlen)
{
	ਜੇ (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_digest_update_ਬਫਰ(ਬਣਤਰ ssh_digest_ctx *ctx, ਅਚਲ ਬਣਤਰ sshbuf *b)
{
	ਵਾਪਸ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

ਪੂਰਨ
ssh_digest_final(ਬਣਤਰ ssh_digest_ctx *ctx, u_char *d, ਮਾਪ_t dlen)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	ਜੇ (digest == ਨਿਰਾ || dlen > UINT_MAX)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (dlen < digest->digest_len) /* No truncation allowed */
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	ਜੇ (l != digest->digest_len) /* sanity */
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
ssh_digest_free(ਬਣਤਰ ssh_digest_ctx *ctx)
{
	ਜੇ (ctx == ਨਿਰਾ)
		ਵਾਪਸ;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, ਆਕਾਰ(*ctx));
}

ਪੂਰਨ
ssh_digest_ਸਮ੍ਰਿਤੀ(ਪੂਰਨ alg, ਅਚਲ ਖਾਲੀ *m, ਮਾਪ_t mlen, u_char *d, ਮਾਪ_t dlen)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	ਜੇ (digest == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (dlen > UINT_MAX)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (dlen < digest->digest_len)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	mdlen = dlen;
	ਜੇ (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), ਨਿਰਾ))
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_digest_ਬਫਰ(ਪੂਰਨ alg, ਅਚਲ ਬਣਤਰ sshbuf *b, u_char *d, ਮਾਪ_t dlen)
{
	ਵਾਪਸ ssh_digest_ਸਮ੍ਰਿਤੀ(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
