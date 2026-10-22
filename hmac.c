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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "hmac.h"

ಸಂರಚನಾ ssh_hmac_ctx {
	ಪೂರ್ಣಾಙ್ಕ			 alg;
	ಸಂರಚನಾ ssh_digest_ctx	*ictx;
	ಸಂರಚನಾ ssh_digest_ctx	*octx;
	ಸಂರಚನಾ ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};

size_t
ssh_hmac_bytes(ಪೂರ್ಣಾಙ್ಕ alg)
{
	ಪ್ರತ್ಯಾಗಮ ssh_digest_bytes(alg);
}

ಸಂರಚನಾ ssh_hmac_ctx *
ssh_hmac_start(ಪೂರ್ಣಾಙ್ಕ alg)
{
	ಸಂರಚನಾ ssh_hmac_ctx	*ret;

	ಯದಿ ((ret = calloc(1, ಪರಿಮಾಣ(*ret))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ret->alg = alg;
	ಯದಿ ((ret->ictx = ssh_digest_start(alg)) == ರಿಕ್ತ ||
	    (ret->octx = ssh_digest_start(alg)) == ರಿಕ್ತ ||
	    (ret->digest = ssh_digest_start(alg)) == ರಿಕ್ತ)
		ಗಚ್ಛ fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	ಯದಿ ((ret->buf = calloc(1, ret->buf_len)) == ರಿಕ್ತ)
		ಗಚ್ಛ fail;
	ಪ್ರತ್ಯಾಗಮ ret;
fail:
	ssh_hmac_free(ret);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_hmac_init(ಸಂರಚನಾ ssh_hmac_ctx *ctx, ಧ್ರುವ ಶೂನ್ಯ *ಕೀಲಿ, size_t klen)
{
	size_t i;

	/* reset ictx and octx if no is key given */
	ಯದಿ (ಕೀಲಿ != ರಿಕ್ತ) {
		/* truncate long keys */
		ಯದಿ (klen <= ctx->buf_len)
			memcpy(ctx->buf, ಕೀಲಿ, klen);
		ಅನ್ಯಥಾ ಯದಿ (ssh_digest_memory(ctx->alg, ಕೀಲಿ, klen, ctx->buf,
		    ctx->buf_len) < 0)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಪ್ರತಿ (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		ಯದಿ (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಪ್ರತಿ (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		ಯದಿ (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			ಪ್ರತ್ಯಾಗಮ -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	ಯದಿ (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_hmac_update(ಸಂರಚನಾ ssh_hmac_ctx *ctx, ಧ್ರುವ ಶೂನ್ಯ *m, size_t mlen)
{
	ಪ್ರತ್ಯಾಗಮ ssh_digest_update(ctx->digest, m, mlen);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_hmac_update_buffer(ಸಂರಚನಾ ssh_hmac_ctx *ctx, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b)
{
	ಪ್ರತ್ಯಾಗಮ ssh_digest_update_buffer(ctx->digest, b);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_hmac_final(ಸಂರಚನಾ ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

	len = ssh_digest_bytes(ctx->alg);
	ಯದಿ (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		ಪ್ರತ್ಯಾಗಮ -1;
	/* switch to octx */
	ಯದಿ (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
ssh_hmac_free(ಸಂರಚನಾ ssh_hmac_ctx *ctx)
{
	ಯದಿ (ctx != ರಿಕ್ತ) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		ಯದಿ (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			ಮುಕ್ತ(ctx->buf);
		}
		freezero(ctx, ಪರಿಮಾಣ(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
ಸ್ಥಿರ ಶೂನ್ಯ
hmac_test(ಶೂನ್ಯ *ಕೀಲಿ, size_t klen, ಶೂನ್ಯ *m, size_t mlen, u_char *e, size_t elen)
{
	ಸಂರಚನಾ ssh_hmac_ctx	*ctx;
	size_t			 i;
	u_char			 digest[16];

	ಯದಿ ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == ರಿಕ್ತ)
		printf("ssh_hmac_start failed");
	ಯದಿ (ssh_hmac_init(ctx, ಕೀಲಿ, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, ಪರಿಮಾಣ(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	ಯದಿ (memcmp(e, digest, elen)) {
		ಪ್ರತಿ (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} ಅನ್ಯಥಾ
		printf("ok\n");
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
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
	memset(key3, 0xaa, ಪರಿಮಾಣ(key3));
	memset(data3, 0xdd, ಪರಿಮಾಣ(data3));

	hmac_test(key1, ಪರಿಮಾಣ(key1), data1, strlen(data1), dig1, ಪರಿಮಾಣ(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, ಪರಿಮಾಣ(dig2));
	hmac_test(key3, ಪರಿಮಾಣ(key3), data3, ಪರಿಮಾಣ(data3), dig3, ಪರಿಮಾಣ(dig3));

	ಪ್ರತ್ಯಾಗಮ 0;
}

#endif
