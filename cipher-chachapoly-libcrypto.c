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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>  /* needed for misc.h */

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "cipher-chachapoly.h"

ರಚನೆ chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *ಶೀರ್ಷಿಕೆ_evp;
};

ರಚನೆ chachapoly_ctx *
chachapoly_new(ಸ್ಥಿರಾಂಕ u_char *ಕೀಲಿ, u_int keylen)
{
	ರಚನೆ chachapoly_ctx *ctx;

	ಆದರೆ (keylen != (32 + 32)) /* 2 x 256 bit keys */
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ ((ctx = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ctx))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ ((ctx->main_evp = EVP_CIPHER_CTX_new()) == ಖಾಲಿ ||
	    (ctx->ಶೀರ್ಷಿಕೆ_evp = EVP_CIPHER_CTX_new()) == ಖಾಲಿ)
		ಹೋಗು fail;
	ಆದರೆ (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), ಕೀಲಿ, ಖಾಲಿ, 1))
		ಹೋಗು fail;
	ಆದರೆ (!EVP_CipherInit(ctx->ಶೀರ್ಷಿಕೆ_evp, EVP_chacha20(), ಕೀಲಿ + 32, ಖಾಲಿ, 1))
		ಹೋಗು fail;
	ಆದರೆ (EVP_CIPHER_CTX_iv_ಉದ್ದಳತೆ(ctx->ಶೀರ್ಷಿಕೆ_evp) != 16)
		ಹೋಗು fail;
	ಹಿಂತಿರುಗಿ ctx;
 fail:
	chachapoly_free(ctx);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಶೂನ್ಯ
chachapoly_free(ರಚನೆ chachapoly_ctx *cpctx)
{
	ಆದರೆ (cpctx == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->ಶೀರ್ಷಿಕೆ_evp);
	freezero(cpctx, ಗಾತ್ರ(*cpctx));
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
ಪೂರ್ಣಾಂಕ
chachapoly_crypt(ರಚನೆ chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ಸ್ಥಿರಾಂಕ u_char *src, u_int len, u_int aadlen, u_int authlen, ಪೂರ್ಣಾಂಕ do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	u_char expected_ಟ್ಯಾಗ್[POLY1305_TAGLEN], poly_ಕೀಲಿ[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, ಗಾತ್ರ(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_ಕೀಲಿ, 0, ಗಾತ್ರ(poly_ಕೀಲಿ));
	ಆದರೆ (!EVP_CipherInit(ctx->main_evp, ಖಾಲಿ, ಖಾಲಿ, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_ಕೀಲಿ,
	    poly_ಕೀಲಿ, ಗಾತ್ರ(poly_ಕೀಲಿ)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* If decrypting, check tag before anything else */
	ಆದರೆ (!do_encrypt) {
		ಸ್ಥಿರಾಂಕ u_char *ಟ್ಯಾಗ್ = src + aadlen + len;

		poly1305_auth(expected_ಟ್ಯಾಗ್, src, aadlen + len, poly_ಕೀಲಿ);
		ಆದರೆ (timingsafe_bcmp(expected_ಟ್ಯಾಗ್, ಟ್ಯಾಗ್, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* Crypt additional data */
	ಆದರೆ (aadlen) {
		ಆದರೆ (!EVP_CipherInit(ctx->ಶೀರ್ಷಿಕೆ_evp, ಖಾಲಿ, ಖಾಲಿ, seqbuf, 1) ||
		    EVP_Cipher(ctx->ಶೀರ್ಷಿಕೆ_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	ಆದರೆ (!EVP_CipherInit(ctx->main_evp, ಖಾಲಿ, ಖಾಲಿ, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* If encrypting, calculate and append tag */
	ಆದರೆ (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_ಕೀಲಿ);
	}
	r = 0;
 ಹೊರಹೋಗು:
	explicit_bzero(expected_ಟ್ಯಾಗ್, ಗಾತ್ರ(expected_ಟ್ಯಾಗ್));
	explicit_bzero(seqbuf, ಗಾತ್ರ(seqbuf));
	explicit_bzero(poly_ಕೀಲಿ, ಗಾತ್ರ(poly_ಕೀಲಿ));
	ಹಿಂತಿರುಗಿ r;
}

/* Decrypt and extract the encrypted packet length */
ಪೂರ್ಣಾಂಕ
chachapoly_get_ಉದ್ದಳತೆ(ರಚನೆ chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ಸ್ಥಿರಾಂಕ u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	ಆದರೆ (len < 4)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	memset(seqbuf, 0, ಗಾತ್ರ(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	ಆದರೆ (!EVP_CipherInit(ctx->ಶೀರ್ಷಿಕೆ_evp, ಖಾಲಿ, ಖಾಲಿ, seqbuf, 0))
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	ಆದರೆ (EVP_Cipher(ctx->ಶೀರ್ಷಿಕೆ_evp, buf, (u_char *)cp, ಗಾತ್ರ(buf)) < 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
