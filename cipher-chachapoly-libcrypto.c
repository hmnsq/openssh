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
#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#endif

#ಯದಿ defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>  /* needed for misc.h */

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "cipher-chachapoly.h"

ಸಂರಚನಾ chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

ಸಂರಚನಾ chachapoly_ctx *
chachapoly_new(ಧ್ರುವ u_char *ಕೀಲಿ, u_int keylen)
{
	ಸಂರಚನಾ chachapoly_ctx *ctx;

	ಯದಿ (keylen != (32 + 32)) /* 2 x 256 bit keys */
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ ((ctx = calloc(1, ಪರಿಮಾಣ(*ctx))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ ((ctx->main_evp = EVP_CIPHER_CTX_new()) == ರಿಕ್ತ ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == ರಿಕ್ತ)
		ಗಚ್ಛ fail;
	ಯದಿ (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), ಕೀಲಿ, ರಿಕ್ತ, 1))
		ಗಚ್ಛ fail;
	ಯದಿ (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), ಕೀಲಿ + 32, ರಿಕ್ತ, 1))
		ಗಚ್ಛ fail;
	ಯದಿ (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		ಗಚ್ಛ fail;
	ಪ್ರತ್ಯಾಗಮ ctx;
 fail:
	chachapoly_free(ctx);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಶೂನ್ಯ
chachapoly_free(ಸಂರಚನಾ chachapoly_ctx *cpctx)
{
	ಯದಿ (cpctx == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, ಪರಿಮಾಣ(*cpctx));
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
ಪೂರ್ಣಾಙ್ಕ
chachapoly_crypt(ಸಂರಚನಾ chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ಧ್ರುವ u_char *src, u_int len, u_int aadlen, u_int authlen, ಪೂರ್ಣಾಙ್ಕ do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_ಕೀಲಿ[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, ಪರಿಮಾಣ(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_ಕೀಲಿ, 0, ಪರಿಮಾಣ(poly_ಕೀಲಿ));
	ಯದಿ (!EVP_CipherInit(ctx->main_evp, ರಿಕ್ತ, ರಿಕ್ತ, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_ಕೀಲಿ,
	    poly_ಕೀಲಿ, ಪರಿಮಾಣ(poly_ಕೀಲಿ)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}

	/* If decrypting, check tag before anything else */
	ಯದಿ (!do_encrypt) {
		ಧ್ರುವ u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_ಕೀಲಿ);
		ಯದಿ (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			ಗಚ್ಛ out;
		}
	}

	/* Crypt additional data */
	ಯದಿ (aadlen) {
		ಯದಿ (!EVP_CipherInit(ctx->header_evp, ರಿಕ್ತ, ರಿಕ್ತ, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	ಯದಿ (!EVP_CipherInit(ctx->main_evp, ರಿಕ್ತ, ರಿಕ್ತ, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}

	/* If encrypting, calculate and append tag */
	ಯದಿ (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_ಕೀಲಿ);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, ಪರಿಮಾಣ(expected_tag));
	explicit_bzero(seqbuf, ಪರಿಮಾಣ(seqbuf));
	explicit_bzero(poly_ಕೀಲಿ, ಪರಿಮಾಣ(poly_ಕೀಲಿ));
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Decrypt and extract the encrypted packet length */
ಪೂರ್ಣಾಙ್ಕ
chachapoly_get_length(ಸಂರಚನಾ chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ಧ್ರುವ u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	ಯದಿ (len < 4)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
	memset(seqbuf, 0, ಪರಿಮಾಣ(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	ಯದಿ (!EVP_CipherInit(ctx->header_evp, ರಿಕ್ತ, ರಿಕ್ತ, seqbuf, 0))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	ಯದಿ (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, ಪರಿಮಾಣ(buf)) < 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
