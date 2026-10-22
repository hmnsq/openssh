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

#অন্তর্ভাব "includes.h"

#ifdef WITH_OPENSSL

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব <openssl/evp.h>

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "ssherr.h"

#ifndef HAVE_EVP_SHA256
# define EVP_sha256 রিক্ত
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 রিক্ত
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 রিক্ত
#endif

সংরচনা ssh_digest_ctx {
	পূর্ণাঙ্ক alg;
	EVP_MD_CTX *mdctx;
};

সংরচনা ssh_digest {
	পূর্ণাঙ্ক id;
	ধ্রুব বর্ণ *name;
	size_t digest_len;
	ধ্রুব EVP_MD *(*mdfunc)(শূন্য);
};

/* NB. Indexed directly by algorithm number */
ধ্রুব সংরচনা ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			রিক্ত,		0,	রিক্ত },
};

স্থির ধ্রুব সংরচনা ssh_digest *
ssh_digest_by_alg(পূর্ণাঙ্ক alg)
{
	যদি (alg < 0 || alg >= SSH_DIGEST_MAX)
		প্রত্যাগম রিক্ত;
	যদি (digests[alg].id != alg) /* sanity */
		প্রত্যাগম রিক্ত;
	যদি (digests[alg].mdfunc == রিক্ত)
		প্রত্যাগম রিক্ত;
	প্রত্যাগম &(digests[alg]);
}

পূর্ণাঙ্ক
ssh_digest_alg_by_name(ধ্রুব বর্ণ *name)
{
	পূর্ণাঙ্ক alg;

	প্রতি (alg = 0; digests[alg].id != -1; alg++) {
		যদি (strcasecmp(name, digests[alg].name) == 0)
			প্রত্যাগম digests[alg].id;
	}
	প্রত্যাগম -1;
}

ধ্রুব বর্ণ *
ssh_digest_alg_name(পূর্ণাঙ্ক alg)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(alg);

	প্রত্যাগম digest == রিক্ত ? রিক্ত : digest->name;
}

size_t
ssh_digest_bytes(পূর্ণাঙ্ক alg)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(alg);

	প্রত্যাগম digest == রিক্ত ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(সংরচনা ssh_digest_ctx *ctx)
{
	প্রত্যাগম EVP_MD_CTX_block_size(ctx->mdctx);
}

সংরচনা ssh_digest_ctx *
ssh_digest_start(পূর্ণাঙ্ক alg)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(alg);
	সংরচনা ssh_digest_ctx *ret;

	যদি (digest == রিক্ত || ((ret = calloc(1, পরিমাণ(*ret))) == রিক্ত))
		প্রত্যাগম রিক্ত;
	ret->alg = alg;
	যদি ((ret->mdctx = EVP_MD_CTX_new()) == রিক্ত) {
		মুক্ত(ret);
		প্রত্যাগম রিক্ত;
	}
	যদি (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), রিক্ত) != 1) {
		ssh_digest_free(ret);
		প্রত্যাগম রিক্ত;
	}
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
ssh_digest_copy_state(সংরচনা ssh_digest_ctx *from, সংরচনা ssh_digest_ctx *to)
{
	যদি (from->alg != to->alg)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	যদি (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
ssh_digest_update(সংরচনা ssh_digest_ctx *ctx, ধ্রুব শূন্য *m, size_t mlen)
{
	যদি (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
ssh_digest_update_buffer(সংরচনা ssh_digest_ctx *ctx, ধ্রুব সংরচনা sshbuf *b)
{
	প্রত্যাগম ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

পূর্ণাঙ্ক
ssh_digest_final(সংরচনা ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	যদি (digest == রিক্ত || dlen > UINT_MAX)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (dlen < digest->digest_len) /* No truncation allowed */
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;
	যদি (l != digest->digest_len) /* sanity */
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	প্রত্যাগম 0;
}

শূন্য
ssh_digest_free(সংরচনা ssh_digest_ctx *ctx)
{
	যদি (ctx == রিক্ত)
		প্রত্যাগম;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, পরিমাণ(*ctx));
}

পূর্ণাঙ্ক
ssh_digest_memory(পূর্ণাঙ্ক alg, ধ্রুব শূন্য *m, size_t mlen, u_char *d, size_t dlen)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	যদি (digest == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (dlen > UINT_MAX)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (dlen < digest->digest_len)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	যদি (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), রিক্ত))
		প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
ssh_digest_buffer(পূর্ণাঙ্ক alg, ধ্রুব সংরচনা sshbuf *b, u_char *d, size_t dlen)
{
	প্রত্যাগম ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
