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

#समावेश "includes.h"
#अगर_घोषित WITH_OPENSSL
#समावेश "openbsd-compat/openssl-compat.h"
#पूर्ण_अगर

#अगर defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#समावेश <sys/types.h>
#समावेश <string.h>
#समावेश <stdio.h>  /* needed for misc.h */

#समावेश <openssl/evp.h>

#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "cipher-chachapoly.h"

काष्ठा chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

काष्ठा chachapoly_ctx *
chachapoly_new(स्थिर u_char *कुंजी, u_int keylen)
{
	काष्ठा chachapoly_ctx *ctx;

	अगर (keylen != (32 + 32)) /* 2 x 256 bit keys */
		वापस शून्य;
	अगर ((ctx = सुस्मृति(1, माप(*ctx))) == शून्य)
		वापस शून्य;
	अगर ((ctx->main_evp = EVP_CIPHER_CTX_new()) == शून्य ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == शून्य)
		जाओ fail;
	अगर (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), कुंजी, शून्य, 1))
		जाओ fail;
	अगर (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), कुंजी + 32, शून्य, 1))
		जाओ fail;
	अगर (EVP_CIPHER_CTX_iv_लंबाई(ctx->header_evp) != 16)
		जाओ fail;
	वापस ctx;
 fail:
	chachapoly_free(ctx);
	वापस शून्य;
}

व्योम
chachapoly_free(काष्ठा chachapoly_ctx *cpctx)
{
	अगर (cpctx == शून्य)
		वापस;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, माप(*cpctx));
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
पूर्णांक
chachapoly_crypt(काष्ठा chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    स्थिर u_char *src, u_int len, u_int aadlen, u_int authlen, पूर्णांक do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_कुंजी[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	स_रखो(seqbuf, 0, माप(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	स_रखो(poly_कुंजी, 0, माप(poly_कुंजी));
	अगर (!EVP_CipherInit(ctx->main_evp, शून्य, शून्य, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_कुंजी,
	    poly_कुंजी, माप(poly_कुंजी)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}

	/* If decrypting, check tag before anything else */
	अगर (!do_encrypt) {
		स्थिर u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_कुंजी);
		अगर (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			जाओ out;
		}
	}

	/* Crypt additional data */
	अगर (aadlen) {
		अगर (!EVP_CipherInit(ctx->header_evp, शून्य, शून्य, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	अगर (!EVP_CipherInit(ctx->main_evp, शून्य, शून्य, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}

	/* If encrypting, calculate and append tag */
	अगर (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_कुंजी);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, माप(expected_tag));
	explicit_bzero(seqbuf, माप(seqbuf));
	explicit_bzero(poly_कुंजी, माप(poly_कुंजी));
	वापस r;
}

/* Decrypt and extract the encrypted packet length */
पूर्णांक
chachapoly_get_लंबाई(काष्ठा chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, स्थिर u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	अगर (len < 4)
		वापस SSH_ERR_MESSAGE_INCOMPLETE;
	स_रखो(seqbuf, 0, माप(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	अगर (!EVP_CipherInit(ctx->header_evp, शून्य, शून्य, seqbuf, 0))
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	अगर (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, माप(buf)) < 0)
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	वापस 0;
}
#पूर्ण_अगर /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
