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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef WITH_OPENSSL

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

#ifndef HAVE_EVP_SHA256
# define EVP_sha256 ଖାଲି
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 ଖାଲି
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 ଖାଲି
#endif

ସଂରଚନା ssh_digest_ctx {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg;
	EVP_MD_CTX *mdctx;
};

ସଂରଚନା ssh_digest {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା id;
	ଅଚଳ ଅକ୍ଷର *name;
	size_t digest_len;
	ଅଚଳ EVP_MD *(*mdfunc)(ଶୂନ୍ୟ);
};

/* NB. Indexed directly by algorithm number */
ଅଚଳ ସଂରଚନା ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			ଖାଲି,		0,	ଖାଲି },
};

ସ୍ଥିର ଅଚଳ ସଂରଚନା ssh_digest *
ssh_digest_by_alg(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	ଯଦି (alg < 0 || alg >= SSH_DIGEST_MAX)
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି (digests[alg].id != alg) /* sanity */
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି (digests[alg].mdfunc == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଫେରନ୍ତୁ &(digests[alg]);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_alg_by_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg;

	ପାଇଁ (alg = 0; digests[alg].id != -1; alg++) {
		ଯଦି (strcasecmp(name, digests[alg].name) == 0)
			ଫେରନ୍ତୁ digests[alg].id;
	}
	ଫେରନ୍ତୁ -1;
}

ଅଚଳ ଅକ୍ଷର *
ssh_digest_alg_name(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(alg);

	ଫେରନ୍ତୁ digest == ଖାଲି ? ଖାଲି : digest->name;
}

size_t
ssh_digest_bytes(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(alg);

	ଫେରନ୍ତୁ digest == ଖାଲି ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(ସଂରଚନା ssh_digest_ctx *ctx)
{
	ଫେରନ୍ତୁ EVP_MD_CTX_block_size(ctx->mdctx);
}

ସଂରଚନା ssh_digest_ctx *
ssh_digest_start(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(alg);
	ସଂରଚନା ssh_digest_ctx *ret;

	ଯଦି (digest == ଖାଲି || ((ret = calloc(1, ଆକାର(*ret))) == ଖାଲି))
		ଫେରନ୍ତୁ ଖାଲି;
	ret->alg = alg;
	ଯଦି ((ret->mdctx = EVP_MD_CTX_new()) == ଖାଲି) {
		ମୁକ୍ତ(ret);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), ଖାଲି) != 1) {
		ssh_digest_free(ret);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_copy_state(ସଂରଚନା ssh_digest_ctx *from, ସଂରଚନା ssh_digest_ctx *to)
{
	ଯଦି (from->alg != to->alg)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	ଯଦି (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_update(ସଂରଚନା ssh_digest_ctx *ctx, ଅଚଳ ଶୂନ୍ୟ *m, size_t mlen)
{
	ଯଦି (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_update_buffer(ସଂରଚନା ssh_digest_ctx *ctx, ଅଚଳ ସଂରଚନା sshbuf *b)
{
	ଫେରନ୍ତୁ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_final(ସଂରଚନା ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	ଯଦି (digest == ଖାଲି || dlen > UINT_MAX)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (dlen < digest->digest_len) /* No truncation allowed */
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	ଯଦି (l != digest->digest_len) /* sanity */
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
ssh_digest_free(ସଂରଚନା ssh_digest_ctx *ctx)
{
	ଯଦି (ctx == ଖାଲି)
		ଫେରନ୍ତୁ;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, ଆକାର(*ctx));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_memory(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ ଶୂନ୍ୟ *m, size_t mlen, u_char *d, size_t dlen)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	ଯଦି (digest == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (dlen > UINT_MAX)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (dlen < digest->digest_len)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	ଯଦି (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), ଖାଲି))
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_buffer(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ ସଂରଚନା sshbuf *b, u_char *d, size_t dlen)
{
	ଫେରନ୍ତୁ ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
