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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే WITH_OPENSSL

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ <openssl/evp.h>

#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "ssherr.h"

#నిర్వచితం_కాకపోతే HAVE_EVP_SHA256
# define EVP_sha256 ఖాళీ
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_EVP_SHA384
# define EVP_sha384 ఖాళీ
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_EVP_SHA512
# define EVP_sha512 ఖాళీ
#అయితే_ముగింపు

నిర్మాణం ssh_digest_ctx {
	పూర్ణాంకం alg;
	EVP_MD_CTX *mdctx;
};

నిర్మాణం ssh_digest {
	పూర్ణాంకం id;
	స్థిరరాశి అక్షరం *name;
	కొలత_t digest_len;
	స్థిరరాశి EVP_MD *(*mdfunc)(శూన్య);
};

/* NB. Indexed directly by algorithm number */
స్థిరరాశి నిర్మాణం ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			ఖాళీ,		0,	ఖాళీ },
};

స్థిర స్థిరరాశి నిర్మాణం ssh_digest *
ssh_digest_by_alg(పూర్ణాంకం alg)
{
	ఒకవేళ (alg < 0 || alg >= SSH_DIGEST_MAX)
		తిరిగి ఖాళీ;
	ఒకవేళ (digests[alg].id != alg) /* sanity */
		తిరిగి ఖాళీ;
	ఒకవేళ (digests[alg].mdfunc == ఖాళీ)
		తిరిగి ఖాళీ;
	తిరిగి &(digests[alg]);
}

పూర్ణాంకం
ssh_digest_alg_by_name(స్థిరరాశి అక్షరం *name)
{
	పూర్ణాంకం alg;

	కొరకు (alg = 0; digests[alg].id != -1; alg++) {
		ఒకవేళ (strcasecmp(name, digests[alg].name) == 0)
			తిరిగి digests[alg].id;
	}
	తిరిగి -1;
}

స్థిరరాశి అక్షరం *
ssh_digest_alg_name(పూర్ణాంకం alg)
{
	స్థిరరాశి నిర్మాణం ssh_digest *digest = ssh_digest_by_alg(alg);

	తిరిగి digest == ఖాళీ ? ఖాళీ : digest->name;
}

కొలత_t
ssh_digest_బైట్లు(పూర్ణాంకం alg)
{
	స్థిరరాశి నిర్మాణం ssh_digest *digest = ssh_digest_by_alg(alg);

	తిరిగి digest == ఖాళీ ? 0 : digest->digest_len;
}

కొలత_t
ssh_digest_blocksize(నిర్మాణం ssh_digest_ctx *ctx)
{
	తిరిగి EVP_MD_CTX_ఖండం_కొలత(ctx->mdctx);
}

నిర్మాణం ssh_digest_ctx *
ssh_digest_ప్రారంభం(పూర్ణాంకం alg)
{
	స్థిరరాశి నిర్మాణం ssh_digest *digest = ssh_digest_by_alg(alg);
	నిర్మాణం ssh_digest_ctx *ret;

	ఒకవేళ (digest == ఖాళీ || ((ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret))) == ఖాళీ))
		తిరిగి ఖాళీ;
	ret->alg = alg;
	ఒకవేళ ((ret->mdctx = EVP_MD_CTX_new()) == ఖాళీ) {
		విడుదల(ret);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), ఖాళీ) != 1) {
		ssh_digest_free(ret);
		తిరిగి ఖాళీ;
	}
	తిరిగి ret;
}

పూర్ణాంకం
ssh_digest_copy_state(నిర్మాణం ssh_digest_ctx *from, నిర్మాణం ssh_digest_ctx *గమ్యం)
{
	ఒకవేళ (from->alg != గమ్యం->alg)
		తిరిగి SSH_ERR_INVALID_వాదం;
	/* we have bcopy-style order while openssl has memcpy-style */
	ఒకవేళ (!EVP_MD_CTX_copy_ex(గమ్యం->mdctx, from->mdctx))
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	తిరిగి 0;
}

పూర్ణాంకం
ssh_digest_update(నిర్మాణం ssh_digest_ctx *ctx, స్థిరరాశి శూన్య *m, కొలత_t mlen)
{
	ఒకవేళ (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	తిరిగి 0;
}

పూర్ణాంకం
ssh_digest_update_బఫరు(నిర్మాణం ssh_digest_ctx *ctx, స్థిరరాశి నిర్మాణం sshbuf *b)
{
	తిరిగి ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

పూర్ణాంకం
ssh_digest_final(నిర్మాణం ssh_digest_ctx *ctx, u_char *d, కొలత_t dlen)
{
	స్థిరరాశి నిర్మాణం ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	ఒకవేళ (digest == ఖాళీ || dlen > UINT_MAX)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (dlen < digest->digest_len) /* No truncation allowed */
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	ఒకవేళ (l != digest->digest_len) /* sanity */
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	తిరిగి 0;
}

శూన్య
ssh_digest_free(నిర్మాణం ssh_digest_ctx *ctx)
{
	ఒకవేళ (ctx == ఖాళీ)
		తిరిగి;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, పరిమాణం(*ctx));
}

పూర్ణాంకం
ssh_digest_జ్ఞాపకం(పూర్ణాంకం alg, స్థిరరాశి శూన్య *m, కొలత_t mlen, u_char *d, కొలత_t dlen)
{
	స్థిరరాశి నిర్మాణం ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	ఒకవేళ (digest == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (dlen > UINT_MAX)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (dlen < digest->digest_len)
		తిరిగి SSH_ERR_INVALID_వాదం;
	mdlen = dlen;
	ఒకవేళ (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), ఖాళీ))
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	తిరిగి 0;
}

పూర్ణాంకం
ssh_digest_బఫరు(పూర్ణాంకం alg, స్థిరరాశి నిర్మాణం sshbuf *b, u_char *d, కొలత_t dlen)
{
	తిరిగి ssh_digest_జ్ఞాపకం(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#అయితే_ముగింపు /* WITH_OPENSSL */
