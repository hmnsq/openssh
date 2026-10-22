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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "digest.h"
#ضمن "hmac.h"

بنية ssh_hmac_ctx {
	صحيح			 alg;
	بنية ssh_digest_ctx	*ictx;
	بنية ssh_digest_ctx	*octx;
	بنية ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};

size_t
ssh_hmac_bytes(صحيح alg)
{
	أرجع ssh_digest_bytes(alg);
}

بنية ssh_hmac_ctx *
ssh_hmac_start(صحيح alg)
{
	بنية ssh_hmac_ctx	*ret;

	𐡄𐡍 ((ret = calloc(1, حجم(*ret))) == عدم)
		أرجع عدم;
	ret->alg = alg;
	𐡄𐡍 ((ret->ictx = ssh_digest_start(alg)) == عدم ||
	    (ret->octx = ssh_digest_start(alg)) == عدم ||
	    (ret->digest = ssh_digest_start(alg)) == عدم)
		اذهب fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	𐡄𐡍 ((ret->buf = calloc(1, ret->buf_len)) == عدم)
		اذهب fail;
	أرجع ret;
fail:
	ssh_hmac_free(ret);
	أرجع عدم;
}

صحيح
ssh_hmac_init(بنية ssh_hmac_ctx *ctx, ثابت فراغ *key, size_t klen)
{
	size_t i;

	/* reset ictx and octx if no is key given */
	𐡄𐡍 (key != عدم) {
		/* truncate long keys */
		𐡄𐡍 (klen <= ctx->buf_len)
			memcpy(ctx->buf, key, klen);
		وإلا 𐡄𐡍 (ssh_digest_memory(ctx->alg, key, klen, ctx->buf,
		    ctx->buf_len) < 0)
			أرجع -1;
		لكل (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		𐡄𐡍 (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			أرجع -1;
		لكل (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		𐡄𐡍 (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			أرجع -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	𐡄𐡍 (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		أرجع -1;
	أرجع 0;
}

صحيح
ssh_hmac_update(بنية ssh_hmac_ctx *ctx, ثابت فراغ *m, size_t mlen)
{
	أرجع ssh_digest_update(ctx->digest, m, mlen);
}

صحيح
ssh_hmac_update_buffer(بنية ssh_hmac_ctx *ctx, ثابت بنية sshbuf *b)
{
	أرجع ssh_digest_update_buffer(ctx->digest, b);
}

صحيح
ssh_hmac_final(بنية ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

	len = ssh_digest_bytes(ctx->alg);
	𐡄𐡍 (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		أرجع -1;
	/* switch to octx */
	𐡄𐡍 (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		أرجع -1;
	أرجع 0;
}

فراغ
ssh_hmac_free(بنية ssh_hmac_ctx *ctx)
{
	𐡄𐡍 (ctx != عدم) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		𐡄𐡍 (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			حرر(ctx->buf);
		}
		freezero(ctx, حجم(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
ساكن فراغ
hmac_test(فراغ *key, size_t klen, فراغ *m, size_t mlen, u_char *e, size_t elen)
{
	بنية ssh_hmac_ctx	*ctx;
	size_t			 i;
	u_char			 digest[16];

	𐡄𐡍 ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == عدم)
		printf("ssh_hmac_start failed");
	𐡄𐡍 (ssh_hmac_init(ctx, key, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, حجم(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	𐡄𐡍 (memcmp(e, digest, elen)) {
		لكل (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} وإلا
		printf("ok\n");
}

صحيح
main(صحيح argc, حرف **argv)
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
	memset(key3, 0xaa, حجم(key3));
	memset(data3, 0xdd, حجم(data3));

	hmac_test(key1, حجم(key1), data1, strlen(data1), dig1, حجم(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, حجم(dig2));
	hmac_test(key3, حجم(key3), data3, حجم(data3), dig3, حجم(dig3));

	أرجع 0;
}

#endif
