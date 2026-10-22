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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే WITH_OPENSSL

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#ఒకవేళ 0
#అన్తర్భావ <md5.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SHA1_H
#అన్తర్భావ <sha1.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SHA2_H
#అన్తర్భావ <sha2.h>
#అయితే_ముగింపు

#ఒకవేళ !defined(SHA256_ఖండం_నిడివి) && defined(SHA256_HMAC_ఖండం_కొలత)
#నిర్వచించు SHA256_ఖండం_నిడివి SHA256_HMAC_ఖండం_కొలత
#అయితే_ముగింపు
#ఒకవేళ !defined(SHA384_ఖండం_నిడివి) && defined(SHA512_HMAC_ఖండం_కొలత)
#నిర్వచించు SHA384_ఖండం_నిడివి SHA512_HMAC_ఖండం_కొలత
#అయితే_ముగింపు
#ఒకవేళ !defined(SHA512_ఖండం_నిడివి) && defined(SHA512_HMAC_ఖండం_కొలత)
#నిర్వచించు SHA512_ఖండం_నిడివి SHA512_HMAC_ఖండం_కొలత
#అయితే_ముగింపు

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "digest.h"

రకనిర్వచనం శూన్య md_init_fn(శూన్య *mdctx);
రకనిర్వచనం శూన్య md_update_fn(శూన్య *mdctx, స్థిరరాశి uint8_t *m, కొలత_t mlen);
రకనిర్వచనం శూన్య md_final_fn(uint8_t[], శూన్య *mdctx);

నిర్మాణం ssh_digest_ctx {
	పూర్ణాంకం alg;
	శూన్య *mdctx;
};

నిర్మాణం ssh_digest {
	పూర్ణాంకం id;
	స్థిరరాశి అక్షరం *name;
	కొలత_t ఖండం_len;
	కొలత_t digest_len;
	కొలత_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
స్థిరరాశి నిర్మాణం ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_ఖండం_నిడివి,
		MD5_DIGEST_నిడివి,
		పరిమాణం(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_ఖండం_నిడివి,
		SHA1_DIGEST_నిడివి,
		పరిమాణం(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_ఖండం_నిడివి,
		SHA256_DIGEST_నిడివి,
		పరిమాణం(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_ఖండం_నిడివి,
		SHA384_DIGEST_నిడివి,
		పరిమాణం(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_ఖండం_నిడివి,
		SHA512_DIGEST_నిడివి,
		పరిమాణం(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

స్థిర స్థిరరాశి నిర్మాణం ssh_digest *
ssh_digest_by_alg(పూర్ణాంకం alg)
{
	ఒకవేళ (alg < 0 || alg >= SSH_DIGEST_MAX)
		తిరిగి ఖాళీ;
	ఒకవేళ (digests[alg].id != alg) /* sanity */
		తిరిగి ఖాళీ;
	తిరిగి &(digests[alg]);
}

పూర్ణాంకం
ssh_digest_alg_by_name(స్థిరరాశి అక్షరం *name)
{
	పూర్ణాంకం alg;

	కొరకు (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
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
	స్థిరరాశి నిర్మాణం ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	తిరిగి digest == ఖాళీ ? 0 : digest->ఖండం_len;
}

నిర్మాణం ssh_digest_ctx *
ssh_digest_ప్రారంభం(పూర్ణాంకం alg)
{
	స్థిరరాశి నిర్మాణం ssh_digest *digest = ssh_digest_by_alg(alg);
	నిర్మాణం ssh_digest_ctx *ret;

	ఒకవేళ (digest == ఖాళీ || (ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret))) == ఖాళీ)
		తిరిగి ఖాళీ;
	ఒకవేళ ((ret->mdctx = సున్నా_జ్ఞాపకం_ఇవ్వు(1, digest->ctx_len)) == ఖాళీ) {
		విడుదల(ret);
		తిరిగి ఖాళీ;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	తిరిగి ret;
}

పూర్ణాంకం
ssh_digest_copy_state(నిర్మాణం ssh_digest_ctx *from, నిర్మాణం ssh_digest_ctx *గమ్యం)
{
	స్థిరరాశి నిర్మాణం ssh_digest *digest = ssh_digest_by_alg(from->alg);

	ఒకవేళ (digest == ఖాళీ || from->alg != గమ్యం->alg)
		తిరిగి SSH_ERR_INVALID_వాదం;
	జ్ఞాపకం_నకలు(గమ్యం->mdctx, from->mdctx, digest->ctx_len);
	తిరిగి 0;
}

పూర్ణాంకం
ssh_digest_update(నిర్మాణం ssh_digest_ctx *ctx, స్థిరరాశి శూన్య *m, కొలత_t mlen)
{
	స్థిరరాశి నిర్మాణం ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ఒకవేళ (digest == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	digest->md_update(ctx->mdctx, m, mlen);
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

	ఒకవేళ (digest == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (dlen > UINT_MAX)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (dlen < digest->digest_len) /* No truncation allowed */
		తిరిగి SSH_ERR_INVALID_వాదం;
	digest->md_final(d, ctx->mdctx);
	తిరిగి 0;
}

శూన్య
ssh_digest_free(నిర్మాణం ssh_digest_ctx *ctx)
{
	స్థిరరాశి నిర్మాణం ssh_digest *digest;

	ఒకవేళ (ctx != ఖాళీ) {
		digest = ssh_digest_by_alg(ctx->alg);
		ఒకవేళ (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			విడుదల(ctx->mdctx);
			freezero(ctx, పరిమాణం(*ctx));
		}
	}
}

పూర్ణాంకం
ssh_digest_జ్ఞాపకం(పూర్ణాంకం alg, స్థిరరాశి శూన్య *m, కొలత_t mlen, u_char *d, కొలత_t dlen)
{
	నిర్మాణం ssh_digest_ctx *ctx = ssh_digest_ప్రారంభం(alg);
	పూర్ణాంకం ret = 0;

	ఒకవేళ (ctx == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_వాదం;
	ssh_digest_free(ctx);
	తిరిగి ret;
}

పూర్ణాంకం
ssh_digest_బఫరు(పూర్ణాంకం alg, స్థిరరాశి నిర్మాణం sshbuf *b, u_char *d, కొలత_t dlen)
{
	తిరిగి ssh_digest_జ్ఞాపకం(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#అయితే_ముగింపు /* !WITH_OPENSSL */
