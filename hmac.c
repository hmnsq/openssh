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

ساخت ssh_hmac_ctx {
	صحیح			 alg;
	ساخت ssh_digest_ctx	*ictx;
	ساخت ssh_digest_ctx	*octx;
	ساخت ssh_digest_ctx	*digest;
	u_char			*buf;
	سائز_t			 buf_len;
};

سائز_t
ssh_hmac_بائٹیں(صحیح alg)
{
	واپس ssh_digest_بائٹیں(alg);
}

ساخت ssh_hmac_ctx *
ssh_hmac_آغاز(صحیح alg)
{
	ساخت ssh_hmac_ctx	*ret;

	اگر ((ret = صفر_حافظہ_دو(1, حجم(*ret))) == تہی)
		واپس تہی;
	ret->alg = alg;
	اگر ((ret->ictx = ssh_digest_آغاز(alg)) == تہی ||
	    (ret->octx = ssh_digest_آغاز(alg)) == تہی ||
	    (ret->digest = ssh_digest_آغاز(alg)) == تہی)
		جاؤ fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	اگر ((ret->buf = صفر_حافظہ_دو(1, ret->buf_len)) == تہی)
		جاؤ fail;
	واپس ret;
fail:
	ssh_hmac_free(ret);
	واپس تہی;
}

صحیح
ssh_hmac_init(ساخت ssh_hmac_ctx *ctx, ثابت خالی *کلید, سائز_t klen)
{
	سائز_t i;

	/* reset ictx and octx if no is key given */
	اگر (کلید != تہی) {
		/* truncate long keys */
		اگر (klen <= ctx->buf_len)
			حافظہ_نقل(ctx->buf, کلید, klen);
		ورنہ اگر (ssh_digest_حافظہ(ctx->alg, کلید, klen, ctx->buf,
		    ctx->buf_len) < 0)
			واپس -1;
		برائے (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		اگر (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			واپس -1;
		برائے (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		اگر (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			واپس -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	اگر (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		واپس -1;
	واپس 0;
}

صحیح
ssh_hmac_update(ساخت ssh_hmac_ctx *ctx, ثابت خالی *m, سائز_t mlen)
{
	واپس ssh_digest_update(ctx->digest, m, mlen);
}

صحیح
ssh_hmac_update_بفر(ساخت ssh_hmac_ctx *ctx, ثابت ساخت sshbuf *b)
{
	واپس ssh_digest_update_بفر(ctx->digest, b);
}

صحیح
ssh_hmac_final(ساخت ssh_hmac_ctx *ctx, u_char *d, سائز_t dlen)
{
	سائز_t len;

	len = ssh_digest_بائٹیں(ctx->alg);
	اگر (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		واپس -1;
	/* switch to octx */
	اگر (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		واپس -1;
	واپس 0;
}

خالی
ssh_hmac_free(ساخت ssh_hmac_ctx *ctx)
{
	اگر (ctx != تہی) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		اگر (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			آزاد(ctx->buf);
		}
		freezero(ctx, حجم(*ctx));
	}
}

#اگر_تعریف_شدہ TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
ساکن خالی
hmac_test(خالی *کلید, سائز_t klen, خالی *m, سائز_t mlen, u_char *e, سائز_t elen)
{
	ساخت ssh_hmac_ctx	*ctx;
	سائز_t			 i;
	u_char			 digest[16];

	اگر ((ctx = ssh_hmac_آغاز(SSH_DIGEST_MD5)) == تہی)
		لکھو("ssh_hmac_start failed");
	اگر (ssh_hmac_init(ctx, کلید, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, حجم(digest)) < 0)
		لکھو("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	اگر (memcmp(e, digest, elen)) {
		برائے (i = 0; i < elen; i++)
			لکھو("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		لکھو("mismatch\n");
	} ورنہ
		لکھو("ok\n");
}

صحیح
مین(صحیح argc, حرف **argv)
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

	hmac_test(key1, حجم(key1), data1, لڑی_لمبائی(data1), dig1, حجم(dig1));
	hmac_test(key2, لڑی_لمبائی(key2), data2, لڑی_لمبائی(data2), dig2, حجم(dig2));
	hmac_test(key3, حجم(key3), data3, حجم(data3), dig3, حجم(dig3));

	واپس 0;
}

#اگر_ختم
