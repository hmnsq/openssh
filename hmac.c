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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdlib.h>
#شامل <string.h>

#شامل "digest.h"
#شامل "hmac.h"

ساختار ssh_hmac_ctx {
	صحیح			 alg;
	ساختار ssh_digest_ctx	*ictx;
	ساختار ssh_digest_ctx	*octx;
	ساختار ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};

size_t
ssh_hmac_bytes(صحیح alg)
{
	بازگشت ssh_digest_bytes(alg);
}

ساختار ssh_hmac_ctx *
ssh_hmac_start(صحیح alg)
{
	ساختار ssh_hmac_ctx	*ret;

	اگر ((ret = calloc(1, اندازه(*ret))) == پوچ)
		بازگشت پوچ;
	ret->alg = alg;
	اگر ((ret->ictx = ssh_digest_start(alg)) == پوچ ||
	    (ret->octx = ssh_digest_start(alg)) == پوچ ||
	    (ret->digest = ssh_digest_start(alg)) == پوچ)
		برو fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	اگر ((ret->buf = calloc(1, ret->buf_len)) == پوچ)
		برو fail;
	بازگشت ret;
fail:
	ssh_hmac_free(ret);
	بازگشت پوچ;
}

صحیح
ssh_hmac_init(ساختار ssh_hmac_ctx *ctx, ثابت تهی *کلید, size_t klen)
{
	size_t i;

	/* reset ictx and octx if no is key given */
	اگر (کلید != پوچ) {
		/* truncate long keys */
		اگر (klen <= ctx->buf_len)
			memcpy(ctx->buf, کلید, klen);
		وگرنه اگر (ssh_digest_memory(ctx->alg, کلید, klen, ctx->buf,
		    ctx->buf_len) < 0)
			بازگشت -1;
		برای (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		اگر (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			بازگشت -1;
		برای (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		اگر (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			بازگشت -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	اگر (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		بازگشت -1;
	بازگشت 0;
}

صحیح
ssh_hmac_update(ساختار ssh_hmac_ctx *ctx, ثابت تهی *m, size_t mlen)
{
	بازگشت ssh_digest_update(ctx->digest, m, mlen);
}

صحیح
ssh_hmac_update_buffer(ساختار ssh_hmac_ctx *ctx, ثابت ساختار sshbuf *b)
{
	بازگشت ssh_digest_update_buffer(ctx->digest, b);
}

صحیح
ssh_hmac_final(ساختار ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

	len = ssh_digest_bytes(ctx->alg);
	اگر (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		بازگشت -1;
	/* switch to octx */
	اگر (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		بازگشت -1;
	بازگشت 0;
}

تهی
ssh_hmac_free(ساختار ssh_hmac_ctx *ctx)
{
	اگر (ctx != پوچ) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		اگر (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			آزاد(ctx->buf);
		}
		freezero(ctx, اندازه(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
ایستا تهی
hmac_test(تهی *کلید, size_t klen, تهی *m, size_t mlen, u_char *e, size_t elen)
{
	ساختار ssh_hmac_ctx	*ctx;
	size_t			 i;
	u_char			 digest[16];

	اگر ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == پوچ)
		printf("ssh_hmac_start failed");
	اگر (ssh_hmac_init(ctx, کلید, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, اندازه(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	اگر (memcmp(e, digest, elen)) {
		برای (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} وگرنه
		printf("ok\n");
}

صحیح
اصلی(صحیح argc, نویسه **argv)
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
	memset(key3, 0xaa, اندازه(key3));
	memset(data3, 0xdd, اندازه(data3));

	hmac_test(key1, اندازه(key1), data1, strlen(data1), dig1, اندازه(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, اندازه(dig2));
	hmac_test(key3, اندازه(key3), data3, اندازه(data3), dig3, اندازه(dig3));

	بازگشت 0;
}

#endif
