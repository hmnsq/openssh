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
# define EVP_sha256 ফাঁকা
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 ফাঁকা
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 ফাঁকা
#endif

কাঠামো ssh_digest_ctx {
	পূর্ণসংখ্যা alg;
	EVP_MD_CTX *mdctx;
};

কাঠামো ssh_digest {
	পূর্ণসংখ্যা id;
	ধ্রুবক অক্ষর *name;
	আকার_t digest_len;
	ধ্রুবক EVP_MD *(*mdfunc)(শূন্য);
};

/* NB. Indexed directly by algorithm number */
ধ্রুবক কাঠামো ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			ফাঁকা,		0,	ফাঁকা },
};

স্থির ধ্রুবক কাঠামো ssh_digest *
ssh_digest_by_alg(পূর্ণসংখ্যা alg)
{
	যদি (alg < 0 || alg >= SSH_DIGEST_MAX)
		ফেরত ফাঁকা;
	যদি (digests[alg].id != alg) /* sanity */
		ফেরত ফাঁকা;
	যদি (digests[alg].mdfunc == ফাঁকা)
		ফেরত ফাঁকা;
	ফেরত &(digests[alg]);
}

পূর্ণসংখ্যা
ssh_digest_alg_by_name(ধ্রুবক অক্ষর *name)
{
	পূর্ণসংখ্যা alg;

	জন্য (alg = 0; digests[alg].id != -1; alg++) {
		যদি (strcasecmp(name, digests[alg].name) == 0)
			ফেরত digests[alg].id;
	}
	ফেরত -1;
}

ধ্রুবক অক্ষর *
ssh_digest_alg_name(পূর্ণসংখ্যা alg)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(alg);

	ফেরত digest == ফাঁকা ? ফাঁকা : digest->name;
}

আকার_t
ssh_digest_bytes(পূর্ণসংখ্যা alg)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(alg);

	ফেরত digest == ফাঁকা ? 0 : digest->digest_len;
}

আকার_t
ssh_digest_blocksize(কাঠামো ssh_digest_ctx *ctx)
{
	ফেরত EVP_MD_CTX_block_আকার(ctx->mdctx);
}

কাঠামো ssh_digest_ctx *
ssh_digest_start(পূর্ণসংখ্যা alg)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(alg);
	কাঠামো ssh_digest_ctx *ret;

	যদি (digest == ফাঁকা || ((ret = calloc(1, আকার(*ret))) == ফাঁকা))
		ফেরত ফাঁকা;
	ret->alg = alg;
	যদি ((ret->mdctx = EVP_MD_CTX_new()) == ফাঁকা) {
		মুক্ত(ret);
		ফেরত ফাঁকা;
	}
	যদি (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), ফাঁকা) != 1) {
		ssh_digest_free(ret);
		ফেরত ফাঁকা;
	}
	ফেরত ret;
}

পূর্ণসংখ্যা
ssh_digest_copy_state(কাঠামো ssh_digest_ctx *from, কাঠামো ssh_digest_ctx *to)
{
	যদি (from->alg != to->alg)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	যদি (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_digest_update(কাঠামো ssh_digest_ctx *ctx, ধ্রুবক শূন্য *m, আকার_t mlen)
{
	যদি (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_digest_update_বাফার(কাঠামো ssh_digest_ctx *ctx, ধ্রুবক কাঠামো sshbuf *b)
{
	ফেরত ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

পূর্ণসংখ্যা
ssh_digest_final(কাঠামো ssh_digest_ctx *ctx, u_char *d, আকার_t dlen)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	যদি (digest == ফাঁকা || dlen > UINT_MAX)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (dlen < digest->digest_len) /* No truncation allowed */
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	যদি (l != digest->digest_len) /* sanity */
		ফেরত SSH_ERR_INTERNAL_ERROR;
	ফেরত 0;
}

শূন্য
ssh_digest_free(কাঠামো ssh_digest_ctx *ctx)
{
	যদি (ctx == ফাঁকা)
		ফেরত;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, আকার(*ctx));
}

পূর্ণসংখ্যা
ssh_digest_memory(পূর্ণসংখ্যা alg, ধ্রুবক শূন্য *m, আকার_t mlen, u_char *d, আকার_t dlen)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	যদি (digest == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (dlen > UINT_MAX)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (dlen < digest->digest_len)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	যদি (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), ফাঁকা))
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_digest_বাফার(পূর্ণসংখ্যা alg, ধ্রুবক কাঠামো sshbuf *b, u_char *d, আকার_t dlen)
{
	ফেরত ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
