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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "hmac.h"

ഘടന ssh_hmac_ctx {
	പൂർണ്ണസംഖ്യ			 alg;
	ഘടന ssh_digest_ctx	*ictx;
	ഘടന ssh_digest_ctx	*octx;
	ഘടന ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
};

size_t
ssh_hmac_bytes(പൂർണ്ണസംഖ്യ alg)
{
	തിരികെ ssh_digest_bytes(alg);
}

ഘടന ssh_hmac_ctx *
ssh_hmac_start(പൂർണ്ണസംഖ്യ alg)
{
	ഘടന ssh_hmac_ctx	*ret;

	എങ്കിൽ ((ret = calloc(1, വലുപ്പം(*ret))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	ret->alg = alg;
	എങ്കിൽ ((ret->ictx = ssh_digest_start(alg)) == ശൂന്യ ||
	    (ret->octx = ssh_digest_start(alg)) == ശൂന്യ ||
	    (ret->digest = ssh_digest_start(alg)) == ശൂന്യ)
		പോകുക fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	എങ്കിൽ ((ret->buf = calloc(1, ret->buf_len)) == ശൂന്യ)
		പോകുക fail;
	തിരികെ ret;
fail:
	ssh_hmac_free(ret);
	തിരികെ ശൂന്യ;
}

പൂർണ്ണസംഖ്യ
ssh_hmac_init(ഘടന ssh_hmac_ctx *ctx, സ്ഥിരം ശൂന്യം *താക്കോൽ, size_t klen)
{
	size_t i;

	/* reset ictx and octx if no is key given */
	എങ്കിൽ (താക്കോൽ != ശൂന്യ) {
		/* truncate long keys */
		എങ്കിൽ (klen <= ctx->buf_len)
			memcpy(ctx->buf, താക്കോൽ, klen);
		അല്ലെങ്കിൽ എങ്കിൽ (ssh_digest_memory(ctx->alg, താക്കോൽ, klen, ctx->buf,
		    ctx->buf_len) < 0)
			തിരികെ -1;
		വേണ്ടി (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		എങ്കിൽ (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			തിരികെ -1;
		വേണ്ടി (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		എങ്കിൽ (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			തിരികെ -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	എങ്കിൽ (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		തിരികെ -1;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_hmac_update(ഘടന ssh_hmac_ctx *ctx, സ്ഥിരം ശൂന്യം *m, size_t mlen)
{
	തിരികെ ssh_digest_update(ctx->digest, m, mlen);
}

പൂർണ്ണസംഖ്യ
ssh_hmac_update_buffer(ഘടന ssh_hmac_ctx *ctx, സ്ഥിരം ഘടന sshbuf *b)
{
	തിരികെ ssh_digest_update_buffer(ctx->digest, b);
}

പൂർണ്ണസംഖ്യ
ssh_hmac_final(ഘടന ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

	len = ssh_digest_bytes(ctx->alg);
	എങ്കിൽ (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		തിരികെ -1;
	/* switch to octx */
	എങ്കിൽ (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		തിരികെ -1;
	തിരികെ 0;
}

ശൂന്യം
ssh_hmac_free(ഘടന ssh_hmac_ctx *ctx)
{
	എങ്കിൽ (ctx != ശൂന്യ) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		എങ്കിൽ (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			സ്വതന്ത്രം(ctx->buf);
		}
		freezero(ctx, വലുപ്പം(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
സ്ഥിതം ശൂന്യം
hmac_test(ശൂന്യം *താക്കോൽ, size_t klen, ശൂന്യം *m, size_t mlen, u_char *e, size_t elen)
{
	ഘടന ssh_hmac_ctx	*ctx;
	size_t			 i;
	u_char			 digest[16];

	എങ്കിൽ ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == ശൂന്യ)
		printf("ssh_hmac_start failed");
	എങ്കിൽ (ssh_hmac_init(ctx, താക്കോൽ, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, വലുപ്പം(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	എങ്കിൽ (memcmp(e, digest, elen)) {
		വേണ്ടി (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} അല്ലെങ്കിൽ
		printf("ok\n");
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
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
	memset(key3, 0xaa, വലുപ്പം(key3));
	memset(data3, 0xdd, വലുപ്പം(data3));

	hmac_test(key1, വലുപ്പം(key1), data1, strlen(data1), dig1, വലുപ്പം(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, വലുപ്പം(dig2));
	hmac_test(key3, വലുപ്പം(key3), data3, വലുപ്പം(data3), dig3, വലുപ്പം(dig3));

	തിരികെ 0;
}

#endif
