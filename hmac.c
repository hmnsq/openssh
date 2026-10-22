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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "digest.h"
#अन्तर्भाव "hmac.h"

संरचना ssh_hmac_ctx {
	पूर्णाङ्क			 alg;
	संरचना ssh_digest_ctx	*ictx;
	संरचना ssh_digest_ctx	*octx;
	संरचना ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};

size_t
ssh_hmac_bytes(पूर्णाङ्क alg)
{
	प्रत्यागम ssh_digest_bytes(alg);
}

संरचना ssh_hmac_ctx *
ssh_hmac_start(पूर्णाङ्क alg)
{
	संरचना ssh_hmac_ctx	*ret;

	जइ ((ret = calloc(1, परिमाण(*ret))) == रिक्त)
		प्रत्यागम रिक्त;
	ret->alg = alg;
	जइ ((ret->ictx = ssh_digest_start(alg)) == रिक्त ||
	    (ret->octx = ssh_digest_start(alg)) == रिक्त ||
	    (ret->digest = ssh_digest_start(alg)) == रिक्त)
		गच्छ fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	जइ ((ret->buf = calloc(1, ret->buf_len)) == रिक्त)
		गच्छ fail;
	प्रत्यागम ret;
fail:
	ssh_hmac_free(ret);
	प्रत्यागम रिक्त;
}

पूर्णाङ्क
ssh_hmac_init(संरचना ssh_hmac_ctx *ctx, ध्रुव शून्य *कुञ्चिका, size_t klen)
{
	size_t i;

	/* reset ictx and octx if no is key given */
	जइ (कुञ्चिका != रिक्त) {
		/* truncate long keys */
		जइ (klen <= ctx->buf_len)
			memcpy(ctx->buf, कुञ्चिका, klen);
		अण्णहा जइ (ssh_digest_memory(ctx->alg, कुञ्चिका, klen, ctx->buf,
		    ctx->buf_len) < 0)
			प्रत्यागम -1;
		प्रति (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		जइ (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			प्रत्यागम -1;
		प्रति (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		जइ (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			प्रत्यागम -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	जइ (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		प्रत्यागम -1;
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_hmac_update(संरचना ssh_hmac_ctx *ctx, ध्रुव शून्य *m, size_t mlen)
{
	प्रत्यागम ssh_digest_update(ctx->digest, m, mlen);
}

पूर्णाङ्क
ssh_hmac_update_buffer(संरचना ssh_hmac_ctx *ctx, ध्रुव संरचना sshbuf *b)
{
	प्रत्यागम ssh_digest_update_buffer(ctx->digest, b);
}

पूर्णाङ्क
ssh_hmac_final(संरचना ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

	len = ssh_digest_bytes(ctx->alg);
	जइ (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		प्रत्यागम -1;
	/* switch to octx */
	जइ (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		प्रत्यागम -1;
	प्रत्यागम 0;
}

शून्य
ssh_hmac_free(संरचना ssh_hmac_ctx *ctx)
{
	जइ (ctx != रिक्त) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		जइ (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			मुक्त(ctx->buf);
		}
		freezero(ctx, परिमाण(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
स्थिर शून्य
hmac_test(शून्य *कुञ्चिका, size_t klen, शून्य *m, size_t mlen, u_char *e, size_t elen)
{
	संरचना ssh_hmac_ctx	*ctx;
	size_t			 i;
	u_char			 digest[16];

	जइ ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == रिक्त)
		printf("ssh_hmac_start failed");
	जइ (ssh_hmac_init(ctx, कुञ्चिका, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, परिमाण(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	जइ (memcmp(e, digest, elen)) {
		प्रति (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} अण्णहा
		printf("ok\n");
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
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
	memset(key3, 0xaa, परिमाण(key3));
	memset(data3, 0xdd, परिमाण(data3));

	hmac_test(key1, परिमाण(key1), data1, strlen(data1), dig1, परिमाण(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, परिमाण(dig2));
	hmac_test(key3, परिमाण(key3), data3, परिमाण(data3), dig3, परिमाण(dig3));

	प्रत्यागम 0;
}

#endif
