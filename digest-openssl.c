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

#ضمن "includes.h"

#ifdef WITH_OPENSSL

#ضمن <sys/types.h>
#ضمن <limits.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <openssl/evp.h>

#ضمن "openbsd-compat/openssl-compat.h"

#ضمن "sshbuf.h"
#ضمن "digest.h"
#ضمن "ssherr.h"

#ifndef HAVE_EVP_SHA256
# define EVP_sha256 عدم
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 عدم
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 عدم
#endif

بنية ssh_digest_ctx {
	صحيح alg;
	EVP_MD_CTX *mdctx;
};

بنية ssh_digest {
	صحيح id;
	ثابت حرف *name;
	size_t digest_len;
	ثابت EVP_MD *(*mdfunc)(فراغ);
};

/* NB. Indexed directly by algorithm number */
ثابت بنية ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			عدم,		0,	عدم },
};

ساكن ثابت بنية ssh_digest *
ssh_digest_by_alg(صحيح alg)
{
	إذا (alg < 0 || alg >= SSH_DIGEST_MAX)
		إرجاع عدم;
	إذا (digests[alg].id != alg) /* sanity */
		إرجاع عدم;
	إذا (digests[alg].mdfunc == عدم)
		إرجاع عدم;
	إرجاع &(digests[alg]);
}

صحيح
ssh_digest_alg_by_name(ثابت حرف *name)
{
	صحيح alg;

	لكل (alg = 0; digests[alg].id != -1; alg++) {
		إذا (strcasecmp(name, digests[alg].name) == 0)
			إرجاع digests[alg].id;
	}
	إرجاع -1;
}

ثابت حرف *
ssh_digest_alg_name(صحيح alg)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(alg);

	إرجاع digest == عدم ? عدم : digest->name;
}

size_t
ssh_digest_bytes(صحيح alg)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(alg);

	إرجاع digest == عدم ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(بنية ssh_digest_ctx *ctx)
{
	إرجاع EVP_MD_CTX_block_size(ctx->mdctx);
}

بنية ssh_digest_ctx *
ssh_digest_start(صحيح alg)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(alg);
	بنية ssh_digest_ctx *ret;

	إذا (digest == عدم || ((ret = calloc(1, حجم(*ret))) == عدم))
		إرجاع عدم;
	ret->alg = alg;
	إذا ((ret->mdctx = EVP_MD_CTX_new()) == عدم) {
		حرر(ret);
		إرجاع عدم;
	}
	إذا (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), عدم) != 1) {
		ssh_digest_free(ret);
		إرجاع عدم;
	}
	إرجاع ret;
}

صحيح
ssh_digest_copy_state(بنية ssh_digest_ctx *from, بنية ssh_digest_ctx *to)
{
	إذا (from->alg != to->alg)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	إذا (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		إرجاع SSH_ERR_LIBCRYPTO_ERROR;
	إرجاع 0;
}

صحيح
ssh_digest_update(بنية ssh_digest_ctx *ctx, ثابت فراغ *m, size_t mlen)
{
	إذا (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		إرجاع SSH_ERR_LIBCRYPTO_ERROR;
	إرجاع 0;
}

صحيح
ssh_digest_update_buffer(بنية ssh_digest_ctx *ctx, ثابت بنية sshbuf *b)
{
	إرجاع ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

صحيح
ssh_digest_final(بنية ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	إذا (digest == عدم || dlen > UINT_MAX)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (dlen < digest->digest_len) /* No truncation allowed */
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		إرجاع SSH_ERR_LIBCRYPTO_ERROR;
	إذا (l != digest->digest_len) /* sanity */
		إرجاع SSH_ERR_INTERNAL_ERROR;
	إرجاع 0;
}

فراغ
ssh_digest_free(بنية ssh_digest_ctx *ctx)
{
	إذا (ctx == عدم)
		إرجاع;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, حجم(*ctx));
}

صحيح
ssh_digest_memory(صحيح alg, ثابت فراغ *m, size_t mlen, u_char *d, size_t dlen)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	إذا (digest == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (dlen > UINT_MAX)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (dlen < digest->digest_len)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	إذا (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), عدم))
		إرجاع SSH_ERR_LIBCRYPTO_ERROR;
	إرجاع 0;
}

صحيح
ssh_digest_buffer(صحيح alg, ثابت بنية sshbuf *b, u_char *d, size_t dlen)
{
	إرجاع ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
