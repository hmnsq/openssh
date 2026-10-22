/* $OpenBSD: hmac.c,v 1.16 2026/02/14 00:18:34 jsg Exp $ */
/*
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

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "digest.h"
#అన్తర్భావ "hmac.h"

నిర్మాణం ssh_hmac_ctx {
	పూర్ణాంకం			 alg;
	నిర్మాణం ssh_digest_ctx	*ictx;
	నిర్మాణం ssh_digest_ctx	*octx;
	నిర్మాణం ssh_digest_ctx	*digest;
	u_char			*buf;
	కొలత_t			 buf_len;
};

కొలత_t
ssh_hmac_బైట్లు(పూర్ణాంకం alg)
{
	తిరిగి ssh_digest_బైట్లు(alg);
}

నిర్మాణం ssh_hmac_ctx *
ssh_hmac_ప్రారంభం(పూర్ణాంకం alg)
{
	నిర్మాణం ssh_hmac_ctx	*ret;

	ఒకవేళ ((ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret))) == ఖాళీ)
		తిరిగి ఖాళీ;
	ret->alg = alg;
	ఒకవేళ ((ret->ictx = ssh_digest_ప్రారంభం(alg)) == ఖాళీ ||
	    (ret->octx = ssh_digest_ప్రారంభం(alg)) == ఖాళీ ||
	    (ret->digest = ssh_digest_ప్రారంభం(alg)) == ఖాళీ)
		వెళ్ళు fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	ఒకవేళ ((ret->buf = సున్నా_జ్ఞాపకం_ఇవ్వు(1, ret->buf_len)) == ఖాళీ)
		వెళ్ళు fail;
	తిరిగి ret;
fail:
	ssh_hmac_free(ret);
	తిరిగి ఖాళీ;
}

పూర్ణాంకం
ssh_hmac_init(నిర్మాణం ssh_hmac_ctx *ctx, స్థిరరాశి శూన్య *కీలకం, కొలత_t klen)
{
	కొలత_t i;

	/* reset ictx and octx if no is key given */
	ఒకవేళ (కీలకం != ఖాళీ) {
		/* truncate long keys */
		ఒకవేళ (klen <= ctx->buf_len)
			జ్ఞాపకం_నకలు(ctx->buf, కీలకం, klen);
		లేకపోతే ఒకవేళ (ssh_digest_జ్ఞాపకం(ctx->alg, కీలకం, klen, ctx->buf,
		    ctx->buf_len) < 0)
			తిరిగి -1;
		కొరకు (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		ఒకవేళ (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			తిరిగి -1;
		కొరకు (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		ఒకవేళ (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			తిరిగి -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	ఒకవేళ (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		తిరిగి -1;
	తిరిగి 0;
}

పూర్ణాంకం
ssh_hmac_update(నిర్మాణం ssh_hmac_ctx *ctx, స్థిరరాశి శూన్య *m, కొలత_t mlen)
{
	తిరిగి ssh_digest_update(ctx->digest, m, mlen);
}

పూర్ణాంకం
ssh_hmac_update_బఫరు(నిర్మాణం ssh_hmac_ctx *ctx, స్థిరరాశి నిర్మాణం sshbuf *b)
{
	తిరిగి ssh_digest_update_బఫరు(ctx->digest, b);
}

పూర్ణాంకం
ssh_hmac_final(నిర్మాణం ssh_hmac_ctx *ctx, u_char *d, కొలత_t dlen)
{
	కొలత_t len;

	len = ssh_digest_బైట్లు(ctx->alg);
	ఒకవేళ (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		తిరిగి -1;
	/* switch to octx */
	ఒకవేళ (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		తిరిగి -1;
	తిరిగి 0;
}

శూన్య
ssh_hmac_free(నిర్మాణం ssh_hmac_ctx *ctx)
{
	ఒకవేళ (ctx != ఖాళీ) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		ఒకవేళ (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			విడుదల(ctx->buf);
		}
		freezero(ctx, పరిమాణం(*ctx));
	}
}

#నిర్వచితమైతే TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
స్థిర శూన్య
hmac_test(శూన్య *కీలకం, కొలత_t klen, శూన్య *m, కొలత_t mlen, u_char *e, కొలత_t elen)
{
	నిర్మాణం ssh_hmac_ctx	*ctx;
	కొలత_t			 i;
	u_char			 digest[16];

	ఒకవేళ ((ctx = ssh_hmac_ప్రారంభం(SSH_DIGEST_MD5)) == ఖాళీ)
		రాయి("ssh_hmac_start failed");
	ఒకవేళ (ssh_hmac_init(ctx, కీలకం, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, పరిమాణం(digest)) < 0)
		రాయి("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	ఒకవేళ (memcmp(e, digest, elen)) {
		కొరకు (i = 0; i < elen; i++)
			రాయి("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		రాయి("mismatch\n");
	} లేకపోతే
		రాయి("ok\n");
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	/* try test vectors from RFC 2104 */

	u_char key1[16] = {
	    0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
	    0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb };
	u_char *data1 = "Hi There";
	u_char dig1[16] = {
	    0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
	    0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d };

	u_char *key2 = "Jefe";
	u_char *data2 = "what do ya want for nothing?";
	u_char dig2[16] = {
	    0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
	    0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38 };

	u_char key3[16];
	u_char data3[50];
	u_char dig3[16] = {
	    0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
	    0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6 };
	memset(key3, 0xaa, పరిమాణం(key3));
	memset(data3, 0xdd, పరిమాణం(data3));

	hmac_test(key1, పరిమాణం(key1), data1, అక్షరశ్రేణి_పొడవు(data1), dig1, పరిమాణం(dig1));
	hmac_test(key2, అక్షరశ్రేణి_పొడవు(key2), data2, అక్షరశ్రేణి_పొడవు(data2), dig2, పరిమాణం(dig2));
	hmac_test(key3, పరిమాణం(key3), data3, పరిమాణం(data3), dig3, పరిమాణం(dig3));

	తిరిగి 0;
}

#అయితే_ముగింపు
