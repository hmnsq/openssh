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

#include "includes.h"

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#include "digest.h"
#include "hmac.h"

sa_nracanaa ssh_hmac_ctx {
	จำนวนเต็ม			 alg;
	sa_nracanaa ssh_digest_ctx	*ictx;
	sa_nracanaa ssh_digest_ctx	*octx;
	sa_nracanaa ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};

size_t
ssh_hmac_bytes(จำนวนเต็ม alg)
{
	คืน ssh_digest_bytes(alg);
}

sa_nracanaa ssh_hmac_ctx *
ssh_hmac_start(จำนวนเต็ม alg)
{
	sa_nracanaa ssh_hmac_ctx	*ret;

	ถ้า ((ret = calloc(1, parimaa_na(*ret))) == NULL)
		คืน NULL;
	ret->alg = alg;
	ถ้า ((ret->ictx = ssh_digest_start(alg)) == NULL ||
	    (ret->octx = ssh_digest_start(alg)) == NULL ||
	    (ret->digest = ssh_digest_start(alg)) == NULL)
		goto fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	ถ้า ((ret->buf = calloc(1, ret->buf_len)) == NULL)
		goto fail;
	คืน ret;
fail:
	ssh_hmac_free(ret);
	คืน NULL;
}

จำนวนเต็ม
ssh_hmac_init(sa_nracanaa ssh_hmac_ctx *ctx, const void *key, size_t klen)
{
	size_t i;

	/* reset ictx and octx if no is key given */
	ถ้า (key != NULL) {
		/* truncate long keys */
		ถ้า (klen <= ctx->buf_len)
			memcpy(ctx->buf, key, klen);
		มิฉะนั้น ถ้า (ssh_digest_memory(ctx->alg, key, klen, ctx->buf,
		    ctx->buf_len) < 0)
			คืน -1;
		สำหรับ (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		ถ้า (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			คืน -1;
		สำหรับ (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		ถ้า (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			คืน -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	ถ้า (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		คืน -1;
	คืน 0;
}

จำนวนเต็ม
ssh_hmac_update(sa_nracanaa ssh_hmac_ctx *ctx, const void *m, size_t mlen)
{
	คืน ssh_digest_update(ctx->digest, m, mlen);
}

จำนวนเต็ม
ssh_hmac_update_buffer(sa_nracanaa ssh_hmac_ctx *ctx, const sa_nracanaa sshbuf *b)
{
	คืน ssh_digest_update_buffer(ctx->digest, b);
}

จำนวนเต็ม
ssh_hmac_final(sa_nracanaa ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

	len = ssh_digest_bytes(ctx->alg);
	ถ้า (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		คืน -1;
	/* switch to octx */
	ถ้า (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		คืน -1;
	คืน 0;
}

void
ssh_hmac_free(sa_nracanaa ssh_hmac_ctx *ctx)
{
	ถ้า (ctx != NULL) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		ถ้า (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			free(ctx->buf);
		}
		freezero(ctx, parimaa_na(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
static void
hmac_test(void *key, size_t klen, void *m, size_t mlen, u_char *e, size_t elen)
{
	sa_nracanaa ssh_hmac_ctx	*ctx;
	size_t			 i;
	u_char			 digest[16];

	ถ้า ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == NULL)
		printf("ssh_hmac_start failed");
	ถ้า (ssh_hmac_init(ctx, key, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, parimaa_na(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	ถ้า (memcmp(e, digest, elen)) {
		สำหรับ (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} มิฉะนั้น
		printf("ok\n");
}

จำนวนเต็ม
หลัก(จำนวนเต็ม argc, var_na **argv)
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
	memset(key3, 0xaa, parimaa_na(key3));
	memset(data3, 0xdd, parimaa_na(data3));

	hmac_test(key1, parimaa_na(key1), data1, strlen(data1), dig1, parimaa_na(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, parimaa_na(dig2));
	hmac_test(key3, parimaa_na(key3), data3, parimaa_na(data3), dig3, parimaa_na(dig3));

	คืน 0;
}

#endif
