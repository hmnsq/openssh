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

#அந்தர்பாவ "includes.h"

#ifdef WITH_OPENSSL

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ <openssl/evp.h>

#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "ssherr.h"

#ifndef HAVE_EVP_SHA256
# define EVP_sha256 வெற்று
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 வெற்று
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 வெற்று
#endif

கட்டமைப்பு ssh_digest_ctx {
	முழு alg;
	EVP_MD_CTX *mdctx;
};

கட்டமைப்பு ssh_digest {
	முழு id;
	மாறிலி எழுத்து *name;
	size_t digest_len;
	மாறிலி EVP_MD *(*mdfunc)(வெறுமை);
};

/* NB. Indexed directly by algorithm number */
மாறிலி கட்டமைப்பு ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			வெற்று,		0,	வெற்று },
};

நிலையான மாறிலி கட்டமைப்பு ssh_digest *
ssh_digest_by_alg(முழு alg)
{
	எனில் (alg < 0 || alg >= SSH_DIGEST_MAX)
		திரும்பு வெற்று;
	எனில் (digests[alg].id != alg) /* sanity */
		திரும்பு வெற்று;
	எனில் (digests[alg].mdfunc == வெற்று)
		திரும்பு வெற்று;
	திரும்பு &(digests[alg]);
}

முழு
ssh_digest_alg_by_name(மாறிலி எழுத்து *name)
{
	முழு alg;

	க்கு (alg = 0; digests[alg].id != -1; alg++) {
		எனில் (strcasecmp(name, digests[alg].name) == 0)
			திரும்பு digests[alg].id;
	}
	திரும்பு -1;
}

மாறிலி எழுத்து *
ssh_digest_alg_name(முழு alg)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(alg);

	திரும்பு digest == வெற்று ? வெற்று : digest->name;
}

size_t
ssh_digest_bytes(முழு alg)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(alg);

	திரும்பு digest == வெற்று ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(கட்டமைப்பு ssh_digest_ctx *ctx)
{
	திரும்பு EVP_MD_CTX_block_size(ctx->mdctx);
}

கட்டமைப்பு ssh_digest_ctx *
ssh_digest_start(முழு alg)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(alg);
	கட்டமைப்பு ssh_digest_ctx *ret;

	எனில் (digest == வெற்று || ((ret = calloc(1, அளவு(*ret))) == வெற்று))
		திரும்பு வெற்று;
	ret->alg = alg;
	எனில் ((ret->mdctx = EVP_MD_CTX_new()) == வெற்று) {
		விடுவி(ret);
		திரும்பு வெற்று;
	}
	எனில் (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), வெற்று) != 1) {
		ssh_digest_free(ret);
		திரும்பு வெற்று;
	}
	திரும்பு ret;
}

முழு
ssh_digest_copy_state(கட்டமைப்பு ssh_digest_ctx *from, கட்டமைப்பு ssh_digest_ctx *to)
{
	எனில் (from->alg != to->alg)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	எனில் (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	திரும்பு 0;
}

முழு
ssh_digest_update(கட்டமைப்பு ssh_digest_ctx *ctx, மாறிலி வெறுமை *m, size_t mlen)
{
	எனில் (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	திரும்பு 0;
}

முழு
ssh_digest_update_buffer(கட்டமைப்பு ssh_digest_ctx *ctx, மாறிலி கட்டமைப்பு sshbuf *b)
{
	திரும்பு ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

முழு
ssh_digest_final(கட்டமைப்பு ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	எனில் (digest == வெற்று || dlen > UINT_MAX)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (dlen < digest->digest_len) /* No truncation allowed */
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	எனில் (l != digest->digest_len) /* sanity */
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	திரும்பு 0;
}

வெறுமை
ssh_digest_free(கட்டமைப்பு ssh_digest_ctx *ctx)
{
	எனில் (ctx == வெற்று)
		திரும்பு;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, அளவு(*ctx));
}

முழு
ssh_digest_memory(முழு alg, மாறிலி வெறுமை *m, size_t mlen, u_char *d, size_t dlen)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	எனில் (digest == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (dlen > UINT_MAX)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (dlen < digest->digest_len)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	எனில் (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), வெற்று))
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	திரும்பு 0;
}

முழு
ssh_digest_buffer(முழு alg, மாறிலி கட்டமைப்பு sshbuf *b, u_char *d, size_t dlen)
{
	திரும்பு ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
