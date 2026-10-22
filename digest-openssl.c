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

#અન્તર્ભાવ "includes.h"

#ifdef WITH_OPENSSL

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ <openssl/evp.h>

#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "ssherr.h"

#ifndef HAVE_EVP_SHA256
# define EVP_sha256 ખાલી
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 ખાલી
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 ખાલી
#endif

સંરચના ssh_digest_ctx {
	પૂર્ણાંક alg;
	EVP_MD_CTX *mdctx;
};

સંરચના ssh_digest {
	પૂર્ણાંક id;
	અચલ અક્ષર *name;
	size_t digest_len;
	અચલ EVP_MD *(*mdfunc)(શૂન્ય);
};

/* NB. Indexed directly by algorithm number */
અચલ સંરચના ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			ખાલી,		0,	ખાલી },
};

સ્થિર અચલ સંરચના ssh_digest *
ssh_digest_by_alg(પૂર્ણાંક alg)
{
	જો (alg < 0 || alg >= SSH_DIGEST_MAX)
		પાછા ખાલી;
	જો (digests[alg].id != alg) /* sanity */
		પાછા ખાલી;
	જો (digests[alg].mdfunc == ખાલી)
		પાછા ખાલી;
	પાછા &(digests[alg]);
}

પૂર્ણાંક
ssh_digest_alg_by_name(અચલ અક્ષર *name)
{
	પૂર્ણાંક alg;

	માટે (alg = 0; digests[alg].id != -1; alg++) {
		જો (strcasecmp(name, digests[alg].name) == 0)
			પાછા digests[alg].id;
	}
	પાછા -1;
}

અચલ અક્ષર *
ssh_digest_alg_name(પૂર્ણાંક alg)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(alg);

	પાછા digest == ખાલી ? ખાલી : digest->name;
}

size_t
ssh_digest_bytes(પૂર્ણાંક alg)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(alg);

	પાછા digest == ખાલી ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(સંરચના ssh_digest_ctx *ctx)
{
	પાછા EVP_MD_CTX_block_size(ctx->mdctx);
}

સંરચના ssh_digest_ctx *
ssh_digest_start(પૂર્ણાંક alg)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(alg);
	સંરચના ssh_digest_ctx *ret;

	જો (digest == ખાલી || ((ret = calloc(1, કદ(*ret))) == ખાલી))
		પાછા ખાલી;
	ret->alg = alg;
	જો ((ret->mdctx = EVP_MD_CTX_new()) == ખાલી) {
		મુક્ત(ret);
		પાછા ખાલી;
	}
	જો (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), ખાલી) != 1) {
		ssh_digest_free(ret);
		પાછા ખાલી;
	}
	પાછા ret;
}

પૂર્ણાંક
ssh_digest_copy_state(સંરચના ssh_digest_ctx *from, સંરચના ssh_digest_ctx *to)
{
	જો (from->alg != to->alg)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	જો (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	પાછા 0;
}

પૂર્ણાંક
ssh_digest_update(સંરચના ssh_digest_ctx *ctx, અચલ શૂન્ય *m, size_t mlen)
{
	જો (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	પાછા 0;
}

પૂર્ણાંક
ssh_digest_update_buffer(સંરચના ssh_digest_ctx *ctx, અચલ સંરચના sshbuf *b)
{
	પાછા ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

પૂર્ણાંક
ssh_digest_final(સંરચના ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	જો (digest == ખાલી || dlen > UINT_MAX)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (dlen < digest->digest_len) /* No truncation allowed */
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	જો (l != digest->digest_len) /* sanity */
		પાછા SSH_ERR_INTERNAL_ERROR;
	પાછા 0;
}

શૂન્ય
ssh_digest_free(સંરચના ssh_digest_ctx *ctx)
{
	જો (ctx == ખાલી)
		પાછા;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, કદ(*ctx));
}

પૂર્ણાંક
ssh_digest_memory(પૂર્ણાંક alg, અચલ શૂન્ય *m, size_t mlen, u_char *d, size_t dlen)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	જો (digest == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (dlen > UINT_MAX)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (dlen < digest->digest_len)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	જો (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), ખાલી))
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	પાછા 0;
}

પૂર્ણાંક
ssh_digest_buffer(પૂર્ણાંક alg, અચલ સંરચના sshbuf *b, u_char *d, size_t dlen)
{
	પાછા ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
