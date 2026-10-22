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
	आकार_t			 buf_len;
};

आकार_t
ssh_hmac_अष्टकानि(पूर्णाङ्क alg)
{
	प्रत्यागम ssh_digest_अष्टकानि(alg);
}

संरचना ssh_hmac_ctx *
ssh_hmac_start(पूर्णाङ्क alg)
{
	संरचना ssh_hmac_ctx	*ret;

	यदि ((ret = शून्यस्मृतिं_देहि(1, परिमाण(*ret))) == रिक्त)
		प्रत्यागम रिक्त;
	ret->alg = alg;
	यदि ((ret->ictx = ssh_digest_start(alg)) == रिक्त ||
	    (ret->octx = ssh_digest_start(alg)) == रिक्त ||
	    (ret->digest = ssh_digest_start(alg)) == रिक्त)
		गच्छ fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	यदि ((ret->buf = शून्यस्मृतिं_देहि(1, ret->buf_len)) == रिक्त)
		गच्छ fail;
	प्रत्यागम ret;
fail:
	ssh_hmac_free(ret);
	प्रत्यागम रिक्त;
}

पूर्णाङ्क
ssh_hmac_init(संरचना ssh_hmac_ctx *ctx, ध्रुव शून्य *कुञ्चिका, आकार_t klen)
{
	आकार_t i;

	/* reset ictx and octx if no is key given */
	यदि (कुञ्चिका != रिक्त) {
		/* truncate long keys */
		यदि (klen <= ctx->buf_len)
			स्मृतिं_प्रतिलिख(ctx->buf, कुञ्चिका, klen);
		अन्यथा यदि (ssh_digest_स्मृतिः(ctx->alg, कुञ्चिका, klen, ctx->buf,
		    ctx->buf_len) < 0)
			प्रत्यागम -1;
		प्रति (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		यदि (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			प्रत्यागम -1;
		प्रति (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		यदि (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			प्रत्यागम -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	यदि (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		प्रत्यागम -1;
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_hmac_update(संरचना ssh_hmac_ctx *ctx, ध्रुव शून्य *m, आकार_t mlen)
{
	प्रत्यागम ssh_digest_update(ctx->digest, m, mlen);
}

पूर्णाङ्क
ssh_hmac_update_बफर(संरचना ssh_hmac_ctx *ctx, ध्रुव संरचना sshbuf *b)
{
	प्रत्यागम ssh_digest_update_बफर(ctx->digest, b);
}

पूर्णाङ्क
ssh_hmac_final(संरचना ssh_hmac_ctx *ctx, u_char *d, आकार_t dlen)
{
	आकार_t len;

	len = ssh_digest_अष्टकानि(ctx->alg);
	यदि (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		प्रत्यागम -1;
	/* switch to octx */
	यदि (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		प्रत्यागम -1;
	प्रत्यागम 0;
}

शून्य
ssh_hmac_free(संरचना ssh_hmac_ctx *ctx)
{
	यदि (ctx != रिक्त) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		यदि (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			मुक्त(ctx->buf);
		}
		freezero(ctx, परिमाण(*ctx));
	}
}

#यदि_परिभाषितम् TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
स्थिर शून्य
hmac_test(शून्य *कुञ्चिका, आकार_t klen, शून्य *m, आकार_t mlen, u_char *e, आकार_t elen)
{
	संरचना ssh_hmac_ctx	*ctx;
	आकार_t			 i;
	u_char			 digest[16];

	यदि ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == रिक्त)
		प्रारूप_लिख("ssh_hmac_start failed");
	यदि (ssh_hmac_init(ctx, कुञ्चिका, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, परिमाण(digest)) < 0)
		प्रारूप_लिख("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	यदि (memcmp(e, digest, elen)) {
		प्रति (i = 0; i < elen; i++)
			प्रारूप_लिख("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		प्रारूप_लिख("mismatch\n");
	} अन्यथा
		प्रारूप_लिख("ok\n");
}

पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
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
	स्मृतिं_पूरय(key3, 0xaa, परिमाण(key3));
	स्मृतिं_पूरय(data3, 0xdd, परिमाण(data3));

	hmac_test(key1, परिमाण(key1), data1, वाक्यदैर्घ्यम्(data1), dig1, परिमाण(dig1));
	hmac_test(key2, वाक्यदैर्घ्यम्(key2), data2, वाक्यदैर्घ्यम्(data2), dig2, परिमाण(dig2));
	hmac_test(key3, परिमाण(key3), data3, परिमाण(data3), dig3, परिमाण(dig3));

	प्रत्यागम 0;
}

#यदि_अन्तः
