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

#समावेश "includes.h"
#अगर_घोषित WITH_OPENSSL
#समावेश "openbsd-compat/openssl-compat.h"
#पूर्ण_अगर

#अगर !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#समावेश <sys/types.h>
#समावेश <stdarg.h> /* needed for log.h */
#समावेश <string.h>
#समावेश <stdio.h>  /* needed for misc.h */

#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "cipher-chachapoly.h"

काष्ठा chachapoly_ctx {
	काष्ठा chacha_ctx main_ctx, header_ctx;
};

काष्ठा chachapoly_ctx *
chachapoly_new(स्थिर u_char *कुंजी, u_int keylen)
{
	काष्ठा chachapoly_ctx *ctx;

	अगर (keylen != (32 + 32)) /* 2 x 256 bit keys */
		वापस शून्य;
	अगर ((ctx = सुस्मृति(1, माप(*ctx))) == शून्य)
		वापस शून्य;
	chacha_keysetup(&ctx->main_ctx, कुंजी, 256);
	chacha_keysetup(&ctx->header_ctx, कुंजी + 32, 256);
	वापस ctx;
}

व्योम
chachapoly_free(काष्ठा chachapoly_ctx *cpctx)
{
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
	u_char seqbuf[8];
	स्थिर u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_कुंजी[POLY1305_KEYLEN];
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	स_रखो(poly_कुंजी, 0, माप(poly_कुंजी));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, शून्य);
	chacha_encrypt_bytes(&ctx->main_ctx,
	    poly_कुंजी, poly_कुंजी, माप(poly_कुंजी));

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
		chacha_ivsetup(&ctx->header_ctx, seqbuf, शून्य);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	}

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

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
	u_char buf[4], seqbuf[8];

	अगर (len < 4)
		वापस SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, शून्य);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	वापस 0;
}

#पूर्ण_अगर /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
