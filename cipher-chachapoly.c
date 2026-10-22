/* $OpenBSD: cipher-chachapoly.c,v 1.10 2023/07/17 05:26:38 djm Exp $ */
/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"
#endif

#ଯଦି !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h> /* needed for log.h */
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>  /* needed for misc.h */

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "cipher-chachapoly.h"

ସଂରଚନା chachapoly_ctx {
	ସଂରଚନା chacha_ctx main_ctx, header_ctx;
};

ସଂରଚନା chachapoly_ctx *
chachapoly_new(ଅଚଳ u_char *ଚାବି, u_int keylen)
{
	ସଂରଚନା chachapoly_ctx *ctx;

	ଯଦି (keylen != (32 + 32)) /* 2 x 256 bit keys */
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି ((ctx = calloc(1, ଆକାର(*ctx))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	chacha_keysetup(&ctx->main_ctx, ଚାବି, 256);
	chacha_keysetup(&ctx->header_ctx, ଚାବି + 32, 256);
	ଫେରନ୍ତୁ ctx;
}

ଶୂନ୍ୟ
chachapoly_free(ସଂରଚନା chachapoly_ctx *cpctx)
{
	freezero(cpctx, ଆକାର(*cpctx));
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
chachapoly_crypt(ସଂରଚନା chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ଅଚଳ u_char *src, u_int len, u_int aadlen, u_int authlen, ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_encrypt)
{
	u_char seqbuf[8];
	ଅଚଳ u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_ଚାବି[POLY1305_KEYLEN];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_ଚାବି, 0, ଆକାର(poly_ଚାବି));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, ଖାଲି);
	chacha_encrypt_bytes(&ctx->main_ctx,
	    poly_ଚାବି, poly_ଚାବି, ଆକାର(poly_ଚାବି));

	/* If decrypting, check tag before anything else */
	ଯଦି (!do_encrypt) {
		ଅଚଳ u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_ଚାବି);
		ଯଦି (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			ଯାଅ out;
		}
	}

	/* Crypt additional data */
	ଯଦି (aadlen) {
		chacha_ivsetup(&ctx->header_ctx, seqbuf, ଖାଲି);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	}

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

	/* If encrypting, calculate and append tag */
	ଯଦି (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_ଚାବି);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, ଆକାର(expected_tag));
	explicit_bzero(seqbuf, ଆକାର(seqbuf));
	explicit_bzero(poly_ଚାବି, ଆକାର(poly_ଚାବି));
	ଫେରନ୍ତୁ r;
}

/* Decrypt and extract the encrypted packet length */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
chachapoly_get_length(ସଂରଚନା chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ଅଚଳ u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[8];

	ଯଦି (len < 4)
		ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, ଖାଲି);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	ଫେରନ୍ତୁ 0;
}

#endif /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
