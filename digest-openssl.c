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
	ध्रुव वर्ण *name;
	size_t digest_len;
	ध्रुव EVP_MD *(*mdfunc)(शून्य);
};

/* NB. Indexed directly by algorithm number */
ध्रुव संरचना ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			रिक्त,		0,	रिक्त },
};

स्थिर ध्रुव संरचना ssh_digest *
ssh_digest_by_alg(पूर्णाङ्क alg)
{
	जइ (alg < 0 || alg >= SSH_DIGEST_MAX)
		प्रत्यागम रिक्त;
	जइ (digests[alg].id != alg) /* sanity */
		प्रत्यागम रिक्त;
	जइ (digests[alg].mdfunc == रिक्त)
		प्रत्यागम रिक्त;
	प्रत्यागम &(digests[alg]);
}

पूर्णाङ्क
ssh_digest_alg_by_name(ध्रुव वर्ण *name)
{
	पूर्णाङ्क alg;

	प्रति (alg = 0; digests[alg].id != -1; alg++) {
		जइ (strcasecmp(name, digests[alg].name) == 0)
			प्रत्यागम digests[alg].id;
	}
	प्रत्यागम -1;
}

ध्रुव वर्ण *
ssh_digest_alg_name(पूर्णाङ्क alg)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(alg);

	प्रत्यागम digest == रिक्त ? रिक्त : digest->name;
}

size_t
ssh_digest_bytes(पूर्णाङ्क alg)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(alg);

	प्रत्यागम digest == रिक्त ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(संरचना ssh_digest_ctx *ctx)
{
	प्रत्यागम EVP_MD_CTX_block_size(ctx->mdctx);
}

संरचना ssh_digest_ctx *
ssh_digest_start(पूर्णाङ्क alg)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(alg);
	संरचना ssh_digest_ctx *ret;

	जइ (digest == रिक्त || ((ret = calloc(1, परिमाण(*ret))) == रिक्त))
		प्रत्यागम रिक्त;
	ret->alg = alg;
	जइ ((ret->mdctx = EVP_MD_CTX_new()) == रिक्त) {
		मुक्त(ret);
		प्रत्यागम रिक्त;
	}
	जइ (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), रिक्त) != 1) {
		ssh_digest_free(ret);
		प्रत्यागम रिक्त;
	}
	प्रत्यागम ret;
}

पूर्णाङ्क
ssh_digest_copy_state(संरचना ssh_digest_ctx *from, संरचना ssh_digest_ctx *to)
{
	जइ (from->alg != to->alg)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	जइ (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_digest_update(संरचना ssh_digest_ctx *ctx, ध्रुव शून्य *m, size_t mlen)
{
	जइ (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_digest_update_buffer(संरचना ssh_digest_ctx *ctx, ध्रुव संरचना sshbuf *b)
{
	प्रत्यागम ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

पूर्णाङ्क
ssh_digest_final(संरचना ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	जइ (digest == रिक्त || dlen > UINT_MAX)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	जइ (dlen < digest->digest_len) /* No truncation allowed */
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	जइ (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	जइ (l != digest->digest_len) /* sanity */
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	प्रत्यागम 0;
}

शून्य
ssh_digest_free(संरचना ssh_digest_ctx *ctx)
{
	जइ (ctx == रिक्त)
		प्रत्यागम;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, परिमाण(*ctx));
}

पूर्णाङ्क
ssh_digest_memory(पूर्णाङ्क alg, ध्रुव शून्य *m, size_t mlen, u_char *d, size_t dlen)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	जइ (digest == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	जइ (dlen > UINT_MAX)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	जइ (dlen < digest->digest_len)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	जइ (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), रिक्त))
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_digest_buffer(पूर्णाङ्क alg, ध्रुव संरचना sshbuf *b, u_char *d, size_t dlen)
{
	प्रत्यागम ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
