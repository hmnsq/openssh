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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "hmac.h"

কাঠামো ssh_hmac_ctx {
	পূর্ণসংখ্যা			 alg;
	কাঠামো ssh_digest_ctx	*ictx;
	কাঠামো ssh_digest_ctx	*octx;
	কাঠামো ssh_digest_ctx	*digest;
	u_char			*buf;
	আকার_t			 buf_len;
};

আকার_t
ssh_hmac_bytes(পূর্ণসংখ্যা alg)
{
	ফেরত ssh_digest_bytes(alg);
}

কাঠামো ssh_hmac_ctx *
ssh_hmac_start(পূর্ণসংখ্যা alg)
{
	কাঠামো ssh_hmac_ctx	*ret;

	যদি ((ret = calloc(1, আকার(*ret))) == ফাঁকা)
		ফেরত ফাঁকা;
	ret->alg = alg;
	যদি ((ret->ictx = ssh_digest_start(alg)) == ফাঁকা ||
	    (ret->octx = ssh_digest_start(alg)) == ফাঁকা ||
	    (ret->digest = ssh_digest_start(alg)) == ফাঁকা)
		যাও fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	যদি ((ret->buf = calloc(1, ret->buf_len)) == ফাঁকা)
		যাও fail;
	ফেরত ret;
fail:
	ssh_hmac_free(ret);
	ফেরত ফাঁকা;
}

পূর্ণসংখ্যা
ssh_hmac_init(কাঠামো ssh_hmac_ctx *ctx, ধ্রুবক শূন্য *চাবি, আকার_t klen)
{
	আকার_t i;

	/* reset ictx and octx if no is key given */
	যদি (চাবি != ফাঁকা) {
		/* truncate long keys */
		যদি (klen <= ctx->buf_len)
			memcpy(ctx->buf, চাবি, klen);
		অন্যথা যদি (ssh_digest_memory(ctx->alg, চাবি, klen, ctx->buf,
		    ctx->buf_len) < 0)
			ফেরত -1;
		জন্য (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		যদি (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			ফেরত -1;
		জন্য (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		যদি (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			ফেরত -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	যদি (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		ফেরত -1;
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_hmac_update(কাঠামো ssh_hmac_ctx *ctx, ধ্রুবক শূন্য *m, আকার_t mlen)
{
	ফেরত ssh_digest_update(ctx->digest, m, mlen);
}

পূর্ণসংখ্যা
ssh_hmac_update_বাফার(কাঠামো ssh_hmac_ctx *ctx, ধ্রুবক কাঠামো sshbuf *b)
{
	ফেরত ssh_digest_update_বাফার(ctx->digest, b);
}

পূর্ণসংখ্যা
ssh_hmac_final(কাঠামো ssh_hmac_ctx *ctx, u_char *d, আকার_t dlen)
{
	আকার_t len;

	len = ssh_digest_bytes(ctx->alg);
	যদি (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		ফেরত -1;
	/* switch to octx */
	যদি (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		ফেরত -1;
	ফেরত 0;
}

শূন্য
ssh_hmac_free(কাঠামো ssh_hmac_ctx *ctx)
{
	যদি (ctx != ফাঁকা) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		যদি (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			মুক্ত(ctx->buf);
		}
		freezero(ctx, আকার(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
স্থির শূন্য
hmac_test(শূন্য *চাবি, আকার_t klen, শূন্য *m, আকার_t mlen, u_char *e, আকার_t elen)
{
	কাঠামো ssh_hmac_ctx	*ctx;
	আকার_t			 i;
	u_char			 digest[16];

	যদি ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == ফাঁকা)
		printf("ssh_hmac_start failed");
	যদি (ssh_hmac_init(ctx, চাবি, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, আকার(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	যদি (memcmp(e, digest, elen)) {
		জন্য (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} অন্যথা
		printf("ok\n");
}

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
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
	memset(key3, 0xaa, আকার(key3));
	memset(data3, 0xdd, আকার(data3));

	hmac_test(key1, আকার(key1), data1, strlen(data1), dig1, আকার(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, আকার(dig2));
	hmac_test(key3, আকার(key3), data3, আকার(data3), dig3, আকার(dig3));

	ফেরত 0;
}

#endif
