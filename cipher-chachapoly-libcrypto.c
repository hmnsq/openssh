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

#जर defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

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
chachapoly_new(स्थिरांक u_char *किल्ली, u_int keylen)
{
	संरचना chachapoly_ctx *ctx;

	जर (keylen != (32 + 32)) /* 2 x 256 bit keys */
		परत रिक्त;
	जर ((ctx = सुस्मृति(1, आकार(*ctx))) == रिक्त)
		परत रिक्त;
	जर ((ctx->main_evp = EVP_CIPHER_CTX_new()) == रिक्त ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == रिक्त)
		जा fail;
	जर (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), किल्ली, रिक्त, 1))
		जा fail;
	जर (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), किल्ली + 32, रिक्त, 1))
		जा fail;
	जर (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		जा fail;
	परत ctx;
 fail:
	chachapoly_free(ctx);
	परत रिक्त;
}

शून्य
chachapoly_free(संरचना chachapoly_ctx *cpctx)
{
	जर (cpctx == रिक्त)
		परत;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, आकार(*cpctx));
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
chachapoly_crypt(संरचना chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    स्थिरांक u_char *src, u_int len, u_int aadlen, u_int authlen, पूर्णांक do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_किल्ली[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	स_रखो(seqbuf, 0, आकार(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	स_रखो(poly_किल्ली, 0, आकार(poly_किल्ली));
	जर (!EVP_CipherInit(ctx->main_evp, रिक्त, रिक्त, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_किल्ली,
	    poly_किल्ली, आकार(poly_किल्ली)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}

	/* If decrypting, check tag before anything else */
	जर (!do_encrypt) {
		स्थिरांक u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_किल्ली);
		जर (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			जा out;
		}
	}

	/* Crypt additional data */
	जर (aadlen) {
		जर (!EVP_CipherInit(ctx->header_evp, रिक्त, रिक्त, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जा out;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	जर (!EVP_CipherInit(ctx->main_evp, रिक्त, रिक्त, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}

	/* If encrypting, calculate and append tag */
	जर (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_किल्ली);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, आकार(expected_tag));
	explicit_bzero(seqbuf, आकार(seqbuf));
	explicit_bzero(poly_किल्ली, आकार(poly_किल्ली));
	परत r;
}

/* Decrypt and extract the encrypted packet length */
पूर्णांक
chachapoly_get_length(संरचना chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, स्थिरांक u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	जर (len < 4)
		परत SSH_ERR_MESSAGE_INCOMPLETE;
	स_रखो(seqbuf, 0, आकार(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	जर (!EVP_CipherInit(ctx->header_evp, रिक्त, रिक्त, seqbuf, 0))
		परत SSH_ERR_LIBCRYPTO_ERROR;
	जर (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, आकार(buf)) < 0)
		परत SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	परत 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
