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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "hmac.h"

ସଂରଚନା ssh_hmac_ctx {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 alg;
	ସଂରଚନା ssh_digest_ctx	*ictx;
	ସଂରଚନା ssh_digest_ctx	*octx;
	ସଂରଚନା ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};

size_t
ssh_hmac_bytes(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	ଫେରନ୍ତୁ ssh_digest_bytes(alg);
}

ସଂରଚନା ssh_hmac_ctx *
ssh_hmac_start(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	ସଂରଚନା ssh_hmac_ctx	*ret;

	ଯଦି ((ret = calloc(1, ଆକାର(*ret))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ret->alg = alg;
	ଯଦି ((ret->ictx = ssh_digest_start(alg)) == ଖାଲି ||
	    (ret->octx = ssh_digest_start(alg)) == ଖାଲି ||
	    (ret->digest = ssh_digest_start(alg)) == ଖାଲି)
		ଯାଅ fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	ଯଦି ((ret->buf = calloc(1, ret->buf_len)) == ଖାଲି)
		ଯାଅ fail;
	ଫେରନ୍ତୁ ret;
fail:
	ssh_hmac_free(ret);
	ଫେରନ୍ତୁ ଖାଲି;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_hmac_init(ସଂରଚନା ssh_hmac_ctx *ctx, ଅଚଳ ଶୂନ୍ୟ *ଚାବି, size_t klen)
{
	size_t i;

	/* reset ictx and octx if no is key given */
	ଯଦି (ଚାବି != ଖାଲି) {
		/* truncate long keys */
		ଯଦି (klen <= ctx->buf_len)
			memcpy(ctx->buf, ଚାବି, klen);
		ଅନ୍ୟଥା ଯଦି (ssh_digest_memory(ctx->alg, ଚାବି, klen, ctx->buf,
		    ctx->buf_len) < 0)
			ଫେରନ୍ତୁ -1;
		ପାଇଁ (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		ଯଦି (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			ଫେରନ୍ତୁ -1;
		ପାଇଁ (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		ଯଦି (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			ଫେରନ୍ତୁ -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	ଯଦି (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_hmac_update(ସଂରଚନା ssh_hmac_ctx *ctx, ଅଚଳ ଶୂନ୍ୟ *m, size_t mlen)
{
	ଫେରନ୍ତୁ ssh_digest_update(ctx->digest, m, mlen);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_hmac_update_buffer(ସଂରଚନା ssh_hmac_ctx *ctx, ଅଚଳ ସଂରଚନା sshbuf *b)
{
	ଫେରନ୍ତୁ ssh_digest_update_buffer(ctx->digest, b);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_hmac_final(ସଂରଚନା ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

	len = ssh_digest_bytes(ctx->alg);
	ଯଦି (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		ଫେରନ୍ତୁ -1;
	/* switch to octx */
	ଯଦି (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
ssh_hmac_free(ସଂରଚନା ssh_hmac_ctx *ctx)
{
	ଯଦି (ctx != ଖାଲି) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		ଯଦି (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			ମୁକ୍ତ(ctx->buf);
		}
		freezero(ctx, ଆକାର(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
ସ୍ଥିର ଶୂନ୍ୟ
hmac_test(ଶୂନ୍ୟ *ଚାବି, size_t klen, ଶୂନ୍ୟ *m, size_t mlen, u_char *e, size_t elen)
{
	ସଂରଚନା ssh_hmac_ctx	*ctx;
	size_t			 i;
	u_char			 digest[16];

	ଯଦି ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == ଖାଲି)
		printf("ssh_hmac_start failed");
	ଯଦି (ssh_hmac_init(ctx, ଚାବି, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, ଆକାର(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	ଯଦି (memcmp(e, digest, elen)) {
		ପାଇଁ (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} ଅନ୍ୟଥା
		printf("ok\n");
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
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
	memset(key3, 0xaa, ଆକାର(key3));
	memset(data3, 0xdd, ଆକାର(data3));

	hmac_test(key1, ଆକାର(key1), data1, strlen(data1), dig1, ଆକାର(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, ଆକାର(dig2));
	hmac_test(key3, ଆକାର(key3), data3, ଆକାର(data3), dig3, ଆକାର(dig3));

	ଫେରନ୍ତୁ 0;
}

#endif
