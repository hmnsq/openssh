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

#समावेश "includes.h"

#अगर_घोषित WITH_OPENSSL

#समावेश <sys/types.h>
#समावेश <limits.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश <openssl/evp.h>

#समावेश "openbsd-compat/openssl-compat.h"

#समावेश "sshbuf.h"
#समावेश "digest.h"
#समावेश "ssherr.h"

#अगर_अघोषित HAVE_EVP_SHA256
# define EVP_sha256 शून्य
#पूर्ण_अगर
#अगर_अघोषित HAVE_EVP_SHA384
# define EVP_sha384 शून्य
#पूर्ण_अगर
#अगर_अघोषित HAVE_EVP_SHA512
# define EVP_sha512 शून्य
#पूर्ण_अगर

काष्ठा ssh_digest_ctx {
	पूर्णांक alg;
	EVP_MD_CTX *mdctx;
};

काष्ठा ssh_digest {
	पूर्णांक id;
	स्थिर अक्षर *name;
	माप_प्रकार digest_len;
	स्थिर EVP_MD *(*mdfunc)(व्योम);
};

/* NB. Indexed directly by algorithm number */
स्थिर काष्ठा ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			शून्य,		0,	शून्य },
};

अटल स्थिर काष्ठा ssh_digest *
ssh_digest_by_alg(पूर्णांक alg)
{
	अगर (alg < 0 || alg >= SSH_DIGEST_MAX)
		वापस शून्य;
	अगर (digests[alg].id != alg) /* sanity */
		वापस शून्य;
	अगर (digests[alg].mdfunc == शून्य)
		वापस शून्य;
	वापस &(digests[alg]);
}

पूर्णांक
ssh_digest_alg_by_name(स्थिर अक्षर *name)
{
	पूर्णांक alg;

	क्रम (alg = 0; digests[alg].id != -1; alg++) {
		अगर (strcasecmp(name, digests[alg].name) == 0)
			वापस digests[alg].id;
	}
	वापस -1;
}

स्थिर अक्षर *
ssh_digest_alg_name(पूर्णांक alg)
{
	स्थिर काष्ठा ssh_digest *digest = ssh_digest_by_alg(alg);

	वापस digest == शून्य ? शून्य : digest->name;
}

माप_प्रकार
ssh_digest_bytes(पूर्णांक alg)
{
	स्थिर काष्ठा ssh_digest *digest = ssh_digest_by_alg(alg);

	वापस digest == शून्य ? 0 : digest->digest_len;
}

माप_प्रकार
ssh_digest_blocksize(काष्ठा ssh_digest_ctx *ctx)
{
	वापस EVP_MD_CTX_block_आकार(ctx->mdctx);
}

काष्ठा ssh_digest_ctx *
ssh_digest_start(पूर्णांक alg)
{
	स्थिर काष्ठा ssh_digest *digest = ssh_digest_by_alg(alg);
	काष्ठा ssh_digest_ctx *ret;

	अगर (digest == शून्य || ((ret = सुस्मृति(1, माप(*ret))) == शून्य))
		वापस शून्य;
	ret->alg = alg;
	अगर ((ret->mdctx = EVP_MD_CTX_new()) == शून्य) {
		मुक्त(ret);
		वापस शून्य;
	}
	अगर (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), शून्य) != 1) {
		ssh_digest_free(ret);
		वापस शून्य;
	}
	वापस ret;
}

पूर्णांक
ssh_digest_copy_state(काष्ठा ssh_digest_ctx *from, काष्ठा ssh_digest_ctx *to)
{
	अगर (from->alg != to->alg)
		वापस SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	अगर (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	वापस 0;
}

पूर्णांक
ssh_digest_update(काष्ठा ssh_digest_ctx *ctx, स्थिर व्योम *m, माप_प्रकार mlen)
{
	अगर (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	वापस 0;
}

पूर्णांक
ssh_digest_update_बफर(काष्ठा ssh_digest_ctx *ctx, स्थिर काष्ठा sshbuf *b)
{
	वापस ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

पूर्णांक
ssh_digest_final(काष्ठा ssh_digest_ctx *ctx, u_char *d, माप_प्रकार dlen)
{
	स्थिर काष्ठा ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	अगर (digest == शून्य || dlen > अच_पूर्णांक_उच्च)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (dlen < digest->digest_len) /* No truncation allowed */
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	अगर (l != digest->digest_len) /* sanity */
		वापस SSH_ERR_INTERNAL_ERROR;
	वापस 0;
}

व्योम
ssh_digest_free(काष्ठा ssh_digest_ctx *ctx)
{
	अगर (ctx == शून्य)
		वापस;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, माप(*ctx));
}

पूर्णांक
ssh_digest_memory(पूर्णांक alg, स्थिर व्योम *m, माप_प्रकार mlen, u_char *d, माप_प्रकार dlen)
{
	स्थिर काष्ठा ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	अगर (digest == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (dlen > अच_पूर्णांक_उच्च)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (dlen < digest->digest_len)
		वापस SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	अगर (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), शून्य))
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	वापस 0;
}

पूर्णांक
ssh_digest_बफर(पूर्णांक alg, स्थिर काष्ठा sshbuf *b, u_char *d, माप_प्रकार dlen)
{
	वापस ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#पूर्ण_अगर /* WITH_OPENSSL */
