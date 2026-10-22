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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hmac.h"

ਬਣਤਰ ssh_hmac_ctx {
	ਪੂਰਨ			 alg;
	ਬਣਤਰ ssh_digest_ctx	*ictx;
	ਬਣਤਰ ssh_digest_ctx	*octx;
	ਬਣਤਰ ssh_digest_ctx	*digest;
	u_char			*buf;
	ਮਾਪ_t			 buf_len;
};

ਮਾਪ_t
ssh_hmac_ਬਾਈਟਾਂ(ਪੂਰਨ alg)
{
	ਵਾਪਸ ssh_digest_ਬਾਈਟਾਂ(alg);
}

ਬਣਤਰ ssh_hmac_ctx *
ssh_hmac_ਸ਼ੁਰੂ(ਪੂਰਨ alg)
{
	ਬਣਤਰ ssh_hmac_ctx	*ret;

	ਜੇ ((ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ret->alg = alg;
	ਜੇ ((ret->ictx = ssh_digest_ਸ਼ੁਰੂ(alg)) == ਨਿਰਾ ||
	    (ret->octx = ssh_digest_ਸ਼ੁਰੂ(alg)) == ਨਿਰਾ ||
	    (ret->digest = ssh_digest_ਸ਼ੁਰੂ(alg)) == ਨਿਰਾ)
		ਜਾਓ fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	ਜੇ ((ret->buf = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ret->buf_len)) == ਨਿਰਾ)
		ਜਾਓ fail;
	ਵਾਪਸ ret;
fail:
	ssh_hmac_free(ret);
	ਵਾਪਸ ਨਿਰਾ;
}

ਪੂਰਨ
ssh_hmac_init(ਬਣਤਰ ssh_hmac_ctx *ctx, ਅਚਲ ਖਾਲੀ *ਕੁੰਜੀ, ਮਾਪ_t klen)
{
	ਮਾਪ_t i;

	/* reset ictx and octx if no is key given */
	ਜੇ (ਕੁੰਜੀ != ਨਿਰਾ) {
		/* truncate long keys */
		ਜੇ (klen <= ctx->buf_len)
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(ctx->buf, ਕੁੰਜੀ, klen);
		ਨਹੀਂਤਾਂ ਜੇ (ssh_digest_ਸਮ੍ਰਿਤੀ(ctx->alg, ਕੁੰਜੀ, klen, ctx->buf,
		    ctx->buf_len) < 0)
			ਵਾਪਸ -1;
		ਲਈ (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		ਜੇ (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			ਵਾਪਸ -1;
		ਲਈ (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		ਜੇ (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			ਵਾਪਸ -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	ਜੇ (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		ਵਾਪਸ -1;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_hmac_update(ਬਣਤਰ ssh_hmac_ctx *ctx, ਅਚਲ ਖਾਲੀ *m, ਮਾਪ_t mlen)
{
	ਵਾਪਸ ssh_digest_update(ctx->digest, m, mlen);
}

ਪੂਰਨ
ssh_hmac_update_ਬਫਰ(ਬਣਤਰ ssh_hmac_ctx *ctx, ਅਚਲ ਬਣਤਰ sshbuf *b)
{
	ਵਾਪਸ ssh_digest_update_ਬਫਰ(ctx->digest, b);
}

ਪੂਰਨ
ssh_hmac_final(ਬਣਤਰ ssh_hmac_ctx *ctx, u_char *d, ਮਾਪ_t dlen)
{
	ਮਾਪ_t len;

	len = ssh_digest_ਬਾਈਟਾਂ(ctx->alg);
	ਜੇ (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		ਵਾਪਸ -1;
	/* switch to octx */
	ਜੇ (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		ਵਾਪਸ -1;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
ssh_hmac_free(ਬਣਤਰ ssh_hmac_ctx *ctx)
{
	ਜੇ (ctx != ਨਿਰਾ) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		ਜੇ (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			ਮੁਕਤ(ctx->buf);
		}
		freezero(ctx, ਆਕਾਰ(*ctx));
	}
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
ਸਥਿਰ ਖਾਲੀ
hmac_test(ਖਾਲੀ *ਕੁੰਜੀ, ਮਾਪ_t klen, ਖਾਲੀ *m, ਮਾਪ_t mlen, u_char *e, ਮਾਪ_t elen)
{
	ਬਣਤਰ ssh_hmac_ctx	*ctx;
	ਮਾਪ_t			 i;
	u_char			 digest[16];

	ਜੇ ((ctx = ssh_hmac_ਸ਼ੁਰੂ(SSH_DIGEST_MD5)) == ਨਿਰਾ)
		ਲਿਖੋ("ssh_hmac_start failed");
	ਜੇ (ssh_hmac_init(ctx, ਕੁੰਜੀ, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, ਆਕਾਰ(digest)) < 0)
		ਲਿਖੋ("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	ਜੇ (memcmp(e, digest, elen)) {
		ਲਈ (i = 0; i < elen; i++)
			ਲਿਖੋ("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		ਲਿਖੋ("mismatch\n");
	} ਨਹੀਂਤਾਂ
		ਲਿਖੋ("ok\n");
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
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
	memset(key3, 0xaa, ਆਕਾਰ(key3));
	memset(data3, 0xdd, ਆਕਾਰ(data3));

	hmac_test(key1, ਆਕਾਰ(key1), data1, ਲੜੀ_ਲੰਬਾਈ(data1), dig1, ਆਕਾਰ(dig1));
	hmac_test(key2, ਲੜੀ_ਲੰਬਾਈ(key2), data2, ਲੜੀ_ਲੰਬਾਈ(data2), dig2, ਆਕਾਰ(dig2));
	hmac_test(key3, ਆਕਾਰ(key3), data3, ਆਕਾਰ(data3), dig3, ਆਕਾਰ(dig3));

	ਵਾਪਸ 0;
}

#ਜੇ_ਅੰਤ
