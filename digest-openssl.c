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

#شامل "includes.h"

#ifdef WITH_OPENSSL

#شامل <sys/types.h>
#شامل <limits.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل <openssl/evp.h>

#شامل "openbsd-compat/openssl-compat.h"

#شامل "sshbuf.h"
#شامل "digest.h"
#شامل "ssherr.h"

#ifndef HAVE_EVP_SHA256
# define EVP_sha256 پوچ
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 پوچ
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 پوچ
#endif

ساختار ssh_digest_ctx {
	صحیح alg;
	EVP_MD_CTX *mdctx;
};

ساختار ssh_digest {
	صحیح id;
	ثابت نویسه *name;
	size_t digest_len;
	ثابت EVP_MD *(*mdfunc)(تهی);
};

/* NB. Indexed directly by algorithm number */
ثابت ساختار ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			پوچ,		0,	پوچ },
};

ایستا ثابت ساختار ssh_digest *
ssh_digest_by_alg(صحیح alg)
{
	اگر (alg < 0 || alg >= SSH_DIGEST_MAX)
		بازگشت پوچ;
	اگر (digests[alg].id != alg) /* sanity */
		بازگشت پوچ;
	اگر (digests[alg].mdfunc == پوچ)
		بازگشت پوچ;
	بازگشت &(digests[alg]);
}

صحیح
ssh_digest_alg_by_name(ثابت نویسه *name)
{
	صحیح alg;

	برای (alg = 0; digests[alg].id != -1; alg++) {
		اگر (strcasecmp(name, digests[alg].name) == 0)
			بازگشت digests[alg].id;
	}
	بازگشت -1;
}

ثابت نویسه *
ssh_digest_alg_name(صحیح alg)
{
	ثابت ساختار ssh_digest *digest = ssh_digest_by_alg(alg);

	بازگشت digest == پوچ ? پوچ : digest->name;
}

size_t
ssh_digest_bytes(صحیح alg)
{
	ثابت ساختار ssh_digest *digest = ssh_digest_by_alg(alg);

	بازگشت digest == پوچ ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(ساختار ssh_digest_ctx *ctx)
{
	بازگشت EVP_MD_CTX_block_size(ctx->mdctx);
}

ساختار ssh_digest_ctx *
ssh_digest_start(صحیح alg)
{
	ثابت ساختار ssh_digest *digest = ssh_digest_by_alg(alg);
	ساختار ssh_digest_ctx *ret;

	اگر (digest == پوچ || ((ret = calloc(1, اندازه(*ret))) == پوچ))
		بازگشت پوچ;
	ret->alg = alg;
	اگر ((ret->mdctx = EVP_MD_CTX_new()) == پوچ) {
		آزاد(ret);
		بازگشت پوچ;
	}
	اگر (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), پوچ) != 1) {
		ssh_digest_free(ret);
		بازگشت پوچ;
	}
	بازگشت ret;
}

صحیح
ssh_digest_copy_state(ساختار ssh_digest_ctx *from, ساختار ssh_digest_ctx *to)
{
	اگر (from->alg != to->alg)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	اگر (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	بازگشت 0;
}

صحیح
ssh_digest_update(ساختار ssh_digest_ctx *ctx, ثابت تهی *m, size_t mlen)
{
	اگر (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	بازگشت 0;
}

صحیح
ssh_digest_update_buffer(ساختار ssh_digest_ctx *ctx, ثابت ساختار sshbuf *b)
{
	بازگشت ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

صحیح
ssh_digest_final(ساختار ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ثابت ساختار ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	اگر (digest == پوچ || dlen > UINT_MAX)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (dlen < digest->digest_len) /* No truncation allowed */
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	اگر (l != digest->digest_len) /* sanity */
		بازگشت SSH_ERR_INTERNAL_ERROR;
	بازگشت 0;
}

تهی
ssh_digest_free(ساختار ssh_digest_ctx *ctx)
{
	اگر (ctx == پوچ)
		بازگشت;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, اندازه(*ctx));
}

صحیح
ssh_digest_memory(صحیح alg, ثابت تهی *m, size_t mlen, u_char *d, size_t dlen)
{
	ثابت ساختار ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	اگر (digest == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (dlen > UINT_MAX)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (dlen < digest->digest_len)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	اگر (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), پوچ))
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	بازگشت 0;
}

صحیح
ssh_digest_buffer(صحیح alg, ثابت ساختار sshbuf *b, u_char *d, size_t dlen)
{
	بازگشت ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
