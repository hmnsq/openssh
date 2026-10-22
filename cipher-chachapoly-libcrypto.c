/* $OpenBSD: cipher-chachapoly-libcrypto.c,v 1.3 2026/02/14 00:18:34 jsg Exp $ */
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

#ଯଦି defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>  /* needed for misc.h */

#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>

#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "cipher-chachapoly.h"

ସଂରଚନା chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

ସଂରଚନା chachapoly_ctx *
chachapoly_new(ଅଚଳ u_char *ଚାବି, u_int keylen)
{
	ସଂରଚନା chachapoly_ctx *ctx;

	ଯଦି (keylen != (32 + 32)) /* 2 x 256 bit keys */
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି ((ctx = calloc(1, ଆକାର(*ctx))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି ((ctx->main_evp = EVP_CIPHER_CTX_new()) == ଖାଲି ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == ଖାଲି)
		ଯାଅ fail;
	ଯଦି (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), ଚାବି, ଖାଲି, 1))
		ଯାଅ fail;
	ଯଦି (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), ଚାବି + 32, ଖାଲି, 1))
		ଯାଅ fail;
	ଯଦି (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		ଯାଅ fail;
	ଫେରନ୍ତୁ ctx;
 fail:
	chachapoly_free(ctx);
	ଫେରନ୍ତୁ ଖାଲି;
}

ଶୂନ୍ୟ
chachapoly_free(ସଂରଚନା chachapoly_ctx *cpctx)
{
	ଯଦି (cpctx == ଖାଲି)
		ଫେରନ୍ତୁ;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
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
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_ଚାବି[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, ଆକାର(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_ଚାବି, 0, ଆକାର(poly_ଚାବି));
	ଯଦି (!EVP_CipherInit(ctx->main_evp, ଖାଲି, ଖାଲି, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_ଚାବି,
	    poly_ଚାବି, ଆକାର(poly_ଚାବି)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}

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
		ଯଦି (!EVP_CipherInit(ctx->header_evp, ଖାଲି, ଖାଲି, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ଯାଅ out;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	ଯଦି (!EVP_CipherInit(ctx->main_evp, ଖାଲି, ଖାଲି, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}

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
	u_char buf[4], seqbuf[16];

	ଯଦି (len < 4)
		ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	memset(seqbuf, 0, ଆକାର(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	ଯଦି (!EVP_CipherInit(ctx->header_evp, ଖାଲି, ଖାଲି, seqbuf, 0))
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	ଯଦି (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, ଆକାର(buf)) < 0)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	ଫେରନ୍ତୁ 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
