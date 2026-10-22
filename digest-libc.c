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

#समावेश "includes.h"

#अगर_अघोषित WITH_OPENSSL

#समावेश <sys/types.h>
#समावेश <limits.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#अगर 0
#समावेश <md5.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_SHA1_H
#समावेश <sha1.h>
#पूर्ण_अगर
#अगर_घोषित HAVE_SHA2_H
#समावेश <sha2.h>
#पूर्ण_अगर

#अगर !defined(SHA256_BLOCK_लंबाई) && defined(SHA256_HMAC_BLOCK_आकार)
#घोषणा SHA256_BLOCK_लंबाई SHA256_HMAC_BLOCK_आकार
#पूर्ण_अगर
#अगर !defined(SHA384_BLOCK_लंबाई) && defined(SHA512_HMAC_BLOCK_आकार)
#घोषणा SHA384_BLOCK_लंबाई SHA512_HMAC_BLOCK_आकार
#पूर्ण_अगर
#अगर !defined(SHA512_BLOCK_लंबाई) && defined(SHA512_HMAC_BLOCK_आकार)
#घोषणा SHA512_BLOCK_लंबाई SHA512_HMAC_BLOCK_आकार
#पूर्ण_अगर

#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "digest.h"

प्रकार व्योम md_init_fn(व्योम *mdctx);
प्रकार व्योम md_update_fn(व्योम *mdctx, स्थिर uint8_t *m, माप_प्रकार mlen);
प्रकार व्योम md_final_fn(uint8_t[], व्योम *mdctx);

काष्ठा ssh_digest_ctx {
	पूर्णांक alg;
	व्योम *mdctx;
};

काष्ठा ssh_digest {
	पूर्णांक id;
	स्थिर अक्षर *name;
	माप_प्रकार block_len;
	माप_प्रकार digest_len;
	माप_प्रकार ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
स्थिर काष्ठा ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_लंबाई,
		MD5_DIGEST_लंबाई,
		माप(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_लंबाई,
		SHA1_DIGEST_लंबाई,
		माप(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_लंबाई,
		SHA256_DIGEST_लंबाई,
		माप(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_लंबाई,
		SHA384_DIGEST_लंबाई,
		माप(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_लंबाई,
		SHA512_DIGEST_लंबाई,
		माप(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

अटल स्थिर काष्ठा ssh_digest *
ssh_digest_by_alg(पूर्णांक alg)
{
	अगर (alg < 0 || alg >= SSH_DIGEST_MAX)
		वापस शून्य;
	अगर (digests[alg].id != alg) /* sanity */
		वापस शून्य;
	वापस &(digests[alg]);
}

पूर्णांक
ssh_digest_alg_by_name(स्थिर अक्षर *name)
{
	पूर्णांक alg;

	क्रम (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
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
	स्थिर काष्ठा ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	वापस digest == शून्य ? 0 : digest->block_len;
}

काष्ठा ssh_digest_ctx *
ssh_digest_start(पूर्णांक alg)
{
	स्थिर काष्ठा ssh_digest *digest = ssh_digest_by_alg(alg);
	काष्ठा ssh_digest_ctx *ret;

	अगर (digest == शून्य || (ret = सुस्मृति(1, माप(*ret))) == शून्य)
		वापस शून्य;
	अगर ((ret->mdctx = सुस्मृति(1, digest->ctx_len)) == शून्य) {
		मुक्त(ret);
		वापस शून्य;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	वापस ret;
}

पूर्णांक
ssh_digest_copy_state(काष्ठा ssh_digest_ctx *from, काष्ठा ssh_digest_ctx *to)
{
	स्थिर काष्ठा ssh_digest *digest = ssh_digest_by_alg(from->alg);

	अगर (digest == शून्य || from->alg != to->alg)
		वापस SSH_ERR_INVALID_ARGUMENT;
	स_नकल(to->mdctx, from->mdctx, digest->ctx_len);
	वापस 0;
}

पूर्णांक
ssh_digest_update(काष्ठा ssh_digest_ctx *ctx, स्थिर व्योम *m, माप_प्रकार mlen)
{
	स्थिर काष्ठा ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	अगर (digest == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
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

	अगर (digest == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (dlen > अच_पूर्णांक_उच्च)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (dlen < digest->digest_len) /* No truncation allowed */
		वापस SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	वापस 0;
}

व्योम
ssh_digest_free(काष्ठा ssh_digest_ctx *ctx)
{
	स्थिर काष्ठा ssh_digest *digest;

	अगर (ctx != शून्य) {
		digest = ssh_digest_by_alg(ctx->alg);
		अगर (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			मुक्त(ctx->mdctx);
			freezero(ctx, माप(*ctx));
		}
	}
}

पूर्णांक
ssh_digest_memory(पूर्णांक alg, स्थिर व्योम *m, माप_प्रकार mlen, u_char *d, माप_प्रकार dlen)
{
	काष्ठा ssh_digest_ctx *ctx = ssh_digest_start(alg);
	पूर्णांक ret = 0;

	अगर (ctx == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	वापस ret;
}

पूर्णांक
ssh_digest_बफर(पूर्णांक alg, स्थिर काष्ठा sshbuf *b, u_char *d, माप_प्रकार dlen)
{
	वापस ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#पूर्ण_अगर /* !WITH_OPENSSL */
