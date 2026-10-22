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

ರಚನೆ ssh_hmac_ctx {
	ಪೂರ್ಣಾಂಕ			 alg;
	ರಚನೆ ssh_digest_ctx	*ictx;
	ರಚನೆ ssh_digest_ctx	*octx;
	ರಚನೆ ssh_digest_ctx	*digest;
	u_char			*buf;
	ಗಾತ್ರ_t			 buf_len;
};

ಗಾತ್ರ_t
ssh_hmac_ಬೈಟುಗಳು(ಪೂರ್ಣಾಂಕ alg)
{
	ಹಿಂತಿರುಗಿ ssh_digest_ಬೈಟುಗಳು(alg);
}

ರಚನೆ ssh_hmac_ctx *
ssh_hmac_ಆರಂಭ(ಪೂರ್ಣಾಂಕ alg)
{
	ರಚನೆ ssh_hmac_ctx	*ret;

	ಆದರೆ ((ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ret->alg = alg;
	ಆದರೆ ((ret->ictx = ssh_digest_ಆರಂಭ(alg)) == ಖಾಲಿ ||
	    (ret->octx = ssh_digest_ಆರಂಭ(alg)) == ಖಾಲಿ ||
	    (ret->digest = ssh_digest_ಆರಂಭ(alg)) == ಖಾಲಿ)
		ಹೋಗು fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	ಆದರೆ ((ret->buf = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ret->buf_len)) == ಖಾಲಿ)
		ಹೋಗು fail;
	ಹಿಂತಿರುಗಿ ret;
fail:
	ssh_hmac_free(ret);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಪೂರ್ಣಾಂಕ
ssh_hmac_init(ರಚನೆ ssh_hmac_ctx *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *ಕೀಲಿ, ಗಾತ್ರ_t klen)
{
	ಗಾತ್ರ_t i;

	/* reset ictx and octx if no is key given */
	ಆದರೆ (ಕೀಲಿ != ಖಾಲಿ) {
		/* truncate long keys */
		ಆದರೆ (klen <= ctx->buf_len)
			ಸ್ಮರಣೆ_ನಕಲು(ctx->buf, ಕೀಲಿ, klen);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ssh_digest_ಸ್ಮರಣೆ(ctx->alg, ಕೀಲಿ, klen, ctx->buf,
		    ctx->buf_len) < 0)
			ಹಿಂತಿರುಗಿ -1;
		ಗಾಗಿ (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		ಆದರೆ (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			ಹಿಂತಿರುಗಿ -1;
		ಗಾಗಿ (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		ಆದರೆ (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			ಹಿಂತಿರುಗಿ -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	ಆದರೆ (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_hmac_update(ರಚನೆ ssh_hmac_ctx *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *m, ಗಾತ್ರ_t mlen)
{
	ಹಿಂತಿರುಗಿ ssh_digest_update(ctx->digest, m, mlen);
}

ಪೂರ್ಣಾಂಕ
ssh_hmac_update_ಬಫರ್(ರಚನೆ ssh_hmac_ctx *ctx, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b)
{
	ಹಿಂತಿರುಗಿ ssh_digest_update_ಬಫರ್(ctx->digest, b);
}

ಪೂರ್ಣಾಂಕ
ssh_hmac_final(ರಚನೆ ssh_hmac_ctx *ctx, u_char *d, ಗಾತ್ರ_t dlen)
{
	ಗಾತ್ರ_t len;

	len = ssh_digest_ಬೈಟುಗಳು(ctx->alg);
	ಆದರೆ (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		ಹಿಂತಿರುಗಿ -1;
	/* switch to octx */
	ಆದರೆ (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
ssh_hmac_free(ರಚನೆ ssh_hmac_ctx *ctx)
{
	ಆದರೆ (ctx != ಖಾಲಿ) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		ಆದರೆ (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			ಬಿಡುಗಡೆ(ctx->buf);
		}
		freezero(ctx, ಗಾತ್ರ(*ctx));
	}
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
ಸ್ಥಿರ ಶೂನ್ಯ
hmac_test(ಶೂನ್ಯ *ಕೀಲಿ, ಗಾತ್ರ_t klen, ಶೂನ್ಯ *m, ಗಾತ್ರ_t mlen, u_char *e, ಗಾತ್ರ_t elen)
{
	ರಚನೆ ssh_hmac_ctx	*ctx;
	ಗಾತ್ರ_t			 i;
	u_char			 digest[16];

	ಆದರೆ ((ctx = ssh_hmac_ಆರಂಭ(SSH_DIGEST_MD5)) == ಖಾಲಿ)
		ಬರೆ("ssh_hmac_start failed");
	ಆದರೆ (ssh_hmac_init(ctx, ಕೀಲಿ, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, ಗಾತ್ರ(digest)) < 0)
		ಬರೆ("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	ಆದರೆ (memcmp(e, digest, elen)) {
		ಗಾಗಿ (i = 0; i < elen; i++)
			ಬರೆ("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		ಬರೆ("mismatch\n");
	} ಇಲ್ಲದಿದ್ದರೆ
		ಬರೆ("ok\n");
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
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
	memset(key3, 0xaa, ಗಾತ್ರ(key3));
	memset(data3, 0xdd, ಗಾತ್ರ(data3));

	hmac_test(key1, ಗಾತ್ರ(key1), data1, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(data1), dig1, ಗಾತ್ರ(dig1));
	hmac_test(key2, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(key2), data2, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(data2), dig2, ಗಾತ್ರ(dig2));
	hmac_test(key3, ಗಾತ್ರ(key3), data3, ಗಾತ್ರ(data3), dig3, ಗಾತ್ರ(dig3));

	ಹಿಂತಿರುಗಿ 0;
}

#ಆದರೆ_ಅಂತ್ಯ
