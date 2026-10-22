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

#अन्तर्भाव "includes.h"

#ifdef WITH_OPENSSL

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव <openssl/evp.h>

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "ssherr.h"

#ifndef HAVE_EVP_SHA256
# define EVP_sha256 रिक्त
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 रिक्त
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 रिक्त
#endif

संरचना ssh_digest_ctx {
	पूर्णाङ्क alg;
	EVP_MD_CTX *mdctx;
};

संरचना ssh_digest {
	पूर्णाङ्क id;
	अचर वर्ण *name;
	माप_प्रकार digest_len;
	अचर EVP_MD *(*mdfunc)(शून्य);
};

/* NB. Indexed directly by algorithm number */
अचर संरचना ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			रिक्त,		0,	रिक्त },
};

स्थिर अचर संरचना ssh_digest *
ssh_digest_by_alg(पूर्णाङ्क alg)
{
	यदि (alg < 0 || alg >= SSH_DIGEST_MAX)
		फर्काऊ रिक्त;
	यदि (digests[alg].id != alg) /* sanity */
		फर्काऊ रिक्त;
	यदि (digests[alg].mdfunc == रिक्त)
		फर्काऊ रिक्त;
	फर्काऊ &(digests[alg]);
}

पूर्णाङ्क
ssh_digest_alg_by_name(अचर वर्ण *name)
{
	पूर्णाङ्क alg;

	लागि (alg = 0; digests[alg].id != -1; alg++) {
		यदि (strcasecmp(name, digests[alg].name) == 0)
			फर्काऊ digests[alg].id;
	}
	फर्काऊ -1;
}

अचर वर्ण *
ssh_digest_alg_name(पूर्णाङ्क alg)
{
	अचर संरचना ssh_digest *digest = ssh_digest_by_alg(alg);

	फर्काऊ digest == रिक्त ? रिक्त : digest->name;
}

माप_प्रकार
ssh_digest_bytes(पूर्णाङ्क alg)
{
	अचर संरचना ssh_digest *digest = ssh_digest_by_alg(alg);

	फर्काऊ digest == रिक्त ? 0 : digest->digest_len;
}

माप_प्रकार
ssh_digest_blocksize(संरचना ssh_digest_ctx *ctx)
{
	फर्काऊ EVP_MD_CTX_block_size(ctx->mdctx);
}

संरचना ssh_digest_ctx *
ssh_digest_start(पूर्णाङ्क alg)
{
	अचर संरचना ssh_digest *digest = ssh_digest_by_alg(alg);
	संरचना ssh_digest_ctx *ret;

	यदि (digest == रिक्त || ((ret = सुस्मृति(1, परिमाण(*ret))) == रिक्त))
		फर्काऊ रिक्त;
	ret->alg = alg;
	यदि ((ret->mdctx = EVP_MD_CTX_new()) == रिक्त) {
		मुक्त(ret);
		फर्काऊ रिक्त;
	}
	यदि (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), रिक्त) != 1) {
		ssh_digest_free(ret);
		फर्काऊ रिक्त;
	}
	फर्काऊ ret;
}

पूर्णाङ्क
ssh_digest_copy_state(संरचना ssh_digest_ctx *from, संरचना ssh_digest_ctx *to)
{
	यदि (from->alg != to->alg)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	यदि (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	फर्काऊ 0;
}

पूर्णाङ्क
ssh_digest_update(संरचना ssh_digest_ctx *ctx, अचर शून्य *m, माप_प्रकार mlen)
{
	यदि (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	फर्काऊ 0;
}

पूर्णाङ्क
ssh_digest_update_buffer(संरचना ssh_digest_ctx *ctx, अचर संरचना sshbuf *b)
{
	फर्काऊ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

पूर्णाङ्क
ssh_digest_final(संरचना ssh_digest_ctx *ctx, u_char *d, माप_प्रकार dlen)
{
	अचर संरचना ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	यदि (digest == रिक्त || dlen > अच_पूर्णांक_उच्च)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (dlen < digest->digest_len) /* No truncation allowed */
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	यदि (l != digest->digest_len) /* sanity */
		फर्काऊ SSH_ERR_INTERNAL_ERROR;
	फर्काऊ 0;
}

शून्य
ssh_digest_free(संरचना ssh_digest_ctx *ctx)
{
	यदि (ctx == रिक्त)
		फर्काऊ;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, परिमाण(*ctx));
}

पूर्णाङ्क
ssh_digest_memory(पूर्णाङ्क alg, अचर शून्य *m, माप_प्रकार mlen, u_char *d, माप_प्रकार dlen)
{
	अचर संरचना ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	यदि (digest == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (dlen > अच_पूर्णांक_उच्च)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (dlen < digest->digest_len)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	यदि (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), रिक्त))
		फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
	फर्काऊ 0;
}

पूर्णाङ्क
ssh_digest_buffer(पूर्णाङ्क alg, अचर संरचना sshbuf *b, u_char *d, माप_प्रकार dlen)
{
	फर्काऊ ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
