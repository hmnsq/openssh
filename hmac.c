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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "hmac.h"

સંરચના ssh_hmac_ctx {
	પૂર્ણાંક			 alg;
	સંરચના ssh_digest_ctx	*ictx;
	સંરચના ssh_digest_ctx	*octx;
	સંરચના ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};

size_t
ssh_hmac_bytes(પૂર્ણાંક alg)
{
	પાછા ssh_digest_bytes(alg);
}

સંરચના ssh_hmac_ctx *
ssh_hmac_start(પૂર્ણાંક alg)
{
	સંરચના ssh_hmac_ctx	*ret;

	જો ((ret = calloc(1, કદ(*ret))) == ખાલી)
		પાછા ખાલી;
	ret->alg = alg;
	જો ((ret->ictx = ssh_digest_start(alg)) == ખાલી ||
	    (ret->octx = ssh_digest_start(alg)) == ખાલી ||
	    (ret->digest = ssh_digest_start(alg)) == ખાલી)
		જાઓ fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	જો ((ret->buf = calloc(1, ret->buf_len)) == ખાલી)
		જાઓ fail;
	પાછા ret;
fail:
	ssh_hmac_free(ret);
	પાછા ખાલી;
}

પૂર્ણાંક
ssh_hmac_init(સંરચના ssh_hmac_ctx *ctx, અચલ શૂન્ય *ચાવી, size_t klen)
{
	size_t i;

	/* reset ictx and octx if no is key given */
	જો (ચાવી != ખાલી) {
		/* truncate long keys */
		જો (klen <= ctx->buf_len)
			memcpy(ctx->buf, ચાવી, klen);
		નહીંતર જો (ssh_digest_memory(ctx->alg, ચાવી, klen, ctx->buf,
		    ctx->buf_len) < 0)
			પાછા -1;
		માટે (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		જો (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			પાછા -1;
		માટે (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		જો (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			પાછા -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	જો (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		પાછા -1;
	પાછા 0;
}

પૂર્ણાંક
ssh_hmac_update(સંરચના ssh_hmac_ctx *ctx, અચલ શૂન્ય *m, size_t mlen)
{
	પાછા ssh_digest_update(ctx->digest, m, mlen);
}

પૂર્ણાંક
ssh_hmac_update_buffer(સંરચના ssh_hmac_ctx *ctx, અચલ સંરચના sshbuf *b)
{
	પાછા ssh_digest_update_buffer(ctx->digest, b);
}

પૂર્ણાંક
ssh_hmac_final(સંરચના ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

	len = ssh_digest_bytes(ctx->alg);
	જો (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		પાછા -1;
	/* switch to octx */
	જો (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		પાછા -1;
	પાછા 0;
}

શૂન્ય
ssh_hmac_free(સંરચના ssh_hmac_ctx *ctx)
{
	જો (ctx != ખાલી) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		જો (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			મુક્ત(ctx->buf);
		}
		freezero(ctx, કદ(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
સ્થિર શૂન્ય
hmac_test(શૂન્ય *ચાવી, size_t klen, શૂન્ય *m, size_t mlen, u_char *e, size_t elen)
{
	સંરચના ssh_hmac_ctx	*ctx;
	size_t			 i;
	u_char			 digest[16];

	જો ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == ખાલી)
		printf("ssh_hmac_start failed");
	જો (ssh_hmac_init(ctx, ચાવી, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, કદ(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	જો (memcmp(e, digest, elen)) {
		માટે (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} નહીંતર
		printf("ok\n");
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
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
	memset(key3, 0xaa, કદ(key3));
	memset(data3, 0xdd, કદ(data3));

	hmac_test(key1, કદ(key1), data1, strlen(data1), dig1, કદ(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, કદ(dig2));
	hmac_test(key3, કદ(key3), data3, કદ(data3), dig3, કદ(dig3));

	પાછા 0;
}

#endif
