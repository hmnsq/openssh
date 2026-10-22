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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "hmac.h"

கட்டமைப்பு ssh_hmac_ctx {
	முழு			 alg;
	கட்டமைப்பு ssh_digest_ctx	*ictx;
	கட்டமைப்பு ssh_digest_ctx	*octx;
	கட்டமைப்பு ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};

size_t
ssh_hmac_bytes(முழு alg)
{
	திரும்பு ssh_digest_bytes(alg);
}

கட்டமைப்பு ssh_hmac_ctx *
ssh_hmac_start(முழு alg)
{
	கட்டமைப்பு ssh_hmac_ctx	*ret;

	எனில் ((ret = calloc(1, அளவு(*ret))) == வெற்று)
		திரும்பு வெற்று;
	ret->alg = alg;
	எனில் ((ret->ictx = ssh_digest_start(alg)) == வெற்று ||
	    (ret->octx = ssh_digest_start(alg)) == வெற்று ||
	    (ret->digest = ssh_digest_start(alg)) == வெற்று)
		செல் fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	எனில் ((ret->buf = calloc(1, ret->buf_len)) == வெற்று)
		செல் fail;
	திரும்பு ret;
fail:
	ssh_hmac_free(ret);
	திரும்பு வெற்று;
}

முழு
ssh_hmac_init(கட்டமைப்பு ssh_hmac_ctx *ctx, மாறிலி வெறுமை *சாவி, size_t klen)
{
	size_t i;

	/* reset ictx and octx if no is key given */
	எனில் (சாவி != வெற்று) {
		/* truncate long keys */
		எனில் (klen <= ctx->buf_len)
			memcpy(ctx->buf, சாவி, klen);
		இல்லையெனில் எனில் (ssh_digest_memory(ctx->alg, சாவி, klen, ctx->buf,
		    ctx->buf_len) < 0)
			திரும்பு -1;
		க்கு (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		எனில் (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			திரும்பு -1;
		க்கு (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		எனில் (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			திரும்பு -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	எனில் (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		திரும்பு -1;
	திரும்பு 0;
}

முழு
ssh_hmac_update(கட்டமைப்பு ssh_hmac_ctx *ctx, மாறிலி வெறுமை *m, size_t mlen)
{
	திரும்பு ssh_digest_update(ctx->digest, m, mlen);
}

முழு
ssh_hmac_update_buffer(கட்டமைப்பு ssh_hmac_ctx *ctx, மாறிலி கட்டமைப்பு sshbuf *b)
{
	திரும்பு ssh_digest_update_buffer(ctx->digest, b);
}

முழு
ssh_hmac_final(கட்டமைப்பு ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

	len = ssh_digest_bytes(ctx->alg);
	எனில் (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		திரும்பு -1;
	/* switch to octx */
	எனில் (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		திரும்பு -1;
	திரும்பு 0;
}

வெறுமை
ssh_hmac_free(கட்டமைப்பு ssh_hmac_ctx *ctx)
{
	எனில் (ctx != வெற்று) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		எனில் (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			விடுவி(ctx->buf);
		}
		freezero(ctx, அளவு(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
நிலையான வெறுமை
hmac_test(வெறுமை *சாவி, size_t klen, வெறுமை *m, size_t mlen, u_char *e, size_t elen)
{
	கட்டமைப்பு ssh_hmac_ctx	*ctx;
	size_t			 i;
	u_char			 digest[16];

	எனில் ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == வெற்று)
		printf("ssh_hmac_start failed");
	எனில் (ssh_hmac_init(ctx, சாவி, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, அளவு(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	எனில் (memcmp(e, digest, elen)) {
		க்கு (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} இல்லையெனில்
		printf("ok\n");
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
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
	memset(key3, 0xaa, அளவு(key3));
	memset(data3, 0xdd, அளவு(data3));

	hmac_test(key1, அளவு(key1), data1, strlen(data1), dig1, அளவு(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, அளவு(dig2));
	hmac_test(key3, அளவு(key3), data3, அளவு(data3), dig3, அளவு(dig3));

	திரும்பு 0;
}

#endif
