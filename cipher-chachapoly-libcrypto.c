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

#अन्तर्भाव "includes.h"
#ifdef WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#endif

#यदि defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdio.h>  /* needed for misc.h */

#अन्तर्भाव <openssl/evp.h>

#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "cipher-chachapoly.h"

संरचना chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

संरचना chachapoly_ctx *
chachapoly_new(ध्रुव u_char *कुंजी, u_int keylen)
{
	संरचना chachapoly_ctx *ctx;

	यदि (keylen != (32 + 32)) /* 2 x 256 bit keys */
		प्रत्यागम रिक्त;
	यदि ((ctx = calloc(1, परिमाण(*ctx))) == रिक्त)
		प्रत्यागम रिक्त;
	यदि ((ctx->main_evp = EVP_CIPHER_CTX_new()) == रिक्त ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == रिक्त)
		गच्छ fail;
	यदि (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), कुंजी, रिक्त, 1))
		गच्छ fail;
	यदि (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), कुंजी + 32, रिक्त, 1))
		गच्छ fail;
	यदि (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		गच्छ fail;
	प्रत्यागम ctx;
 fail:
	chachapoly_free(ctx);
	प्रत्यागम रिक्त;
}

शून्य
chachapoly_free(संरचना chachapoly_ctx *cpctx)
{
	यदि (cpctx == रिक्त)
		प्रत्यागम;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, परिमाण(*cpctx));
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
पूर्णाङ्क
chachapoly_crypt(संरचना chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ध्रुव u_char *src, u_int len, u_int aadlen, u_int authlen, पूर्णाङ्क do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_कुंजी[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, परिमाण(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_कुंजी, 0, परिमाण(poly_कुंजी));
	यदि (!EVP_CipherInit(ctx->main_evp, रिक्त, रिक्त, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_कुंजी,
	    poly_कुंजी, परिमाण(poly_कुंजी)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}

	/* If decrypting, check tag before anything else */
	यदि (!do_encrypt) {
		ध्रुव u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_कुंजी);
		यदि (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			गच्छ out;
		}
	}

	/* Crypt additional data */
	यदि (aadlen) {
		यदि (!EVP_CipherInit(ctx->header_evp, रिक्त, रिक्त, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	यदि (!EVP_CipherInit(ctx->main_evp, रिक्त, रिक्त, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}

	/* If encrypting, calculate and append tag */
	यदि (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_कुंजी);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, परिमाण(expected_tag));
	explicit_bzero(seqbuf, परिमाण(seqbuf));
	explicit_bzero(poly_कुंजी, परिमाण(poly_कुंजी));
	प्रत्यागम r;
}

/* Decrypt and extract the encrypted packet length */
पूर्णाङ्क
chachapoly_get_length(संरचना chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ध्रुव u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	यदि (len < 4)
		प्रत्यागम SSH_ERR_MESSAGE_INCOMPLETE;
	memset(seqbuf, 0, परिमाण(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	यदि (!EVP_CipherInit(ctx->header_evp, रिक्त, रिक्त, seqbuf, 0))
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	यदि (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, परिमाण(buf)) < 0)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	प्रत्यागम 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
