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

#അന്തര്ഭാവ "includes.h"
#ifdef WITH_OPENSSL
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"
#endif

#എങ്കിൽ defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdio.h>  /* needed for misc.h */

#അന്തര്ഭാവ <openssl/evp.h>

#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "cipher-chachapoly.h"

ഘടന chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

ഘടന chachapoly_ctx *
chachapoly_new(സ്ഥിരം u_char *താക്കോൽ, u_int keylen)
{
	ഘടന chachapoly_ctx *ctx;

	എങ്കിൽ (keylen != (32 + 32)) /* 2 x 256 bit keys */
		തിരികെ ശൂന്യ;
	എങ്കിൽ ((ctx = calloc(1, വലുപ്പം(*ctx))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	എങ്കിൽ ((ctx->main_evp = EVP_CIPHER_CTX_new()) == ശൂന്യ ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == ശൂന്യ)
		പോകുക fail;
	എങ്കിൽ (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), താക്കോൽ, ശൂന്യ, 1))
		പോകുക fail;
	എങ്കിൽ (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), താക്കോൽ + 32, ശൂന്യ, 1))
		പോകുക fail;
	എങ്കിൽ (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		പോകുക fail;
	തിരികെ ctx;
 fail:
	chachapoly_free(ctx);
	തിരികെ ശൂന്യ;
}

ശൂന്യം
chachapoly_free(ഘടന chachapoly_ctx *cpctx)
{
	എങ്കിൽ (cpctx == ശൂന്യ)
		തിരികെ;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, വലുപ്പം(*cpctx));
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
പൂർണ്ണസംഖ്യ
chachapoly_crypt(ഘടന chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    സ്ഥിരം u_char *src, u_int len, u_int aadlen, u_int authlen, പൂർണ്ണസംഖ്യ do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_താക്കോൽ[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, വലുപ്പം(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_താക്കോൽ, 0, വലുപ്പം(poly_താക്കോൽ));
	എങ്കിൽ (!EVP_CipherInit(ctx->main_evp, ശൂന്യ, ശൂന്യ, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_താക്കോൽ,
	    poly_താക്കോൽ, വലുപ്പം(poly_താക്കോൽ)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}

	/* If decrypting, check tag before anything else */
	എങ്കിൽ (!do_encrypt) {
		സ്ഥിരം u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_താക്കോൽ);
		എങ്കിൽ (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			പോകുക out;
		}
	}

	/* Crypt additional data */
	എങ്കിൽ (aadlen) {
		എങ്കിൽ (!EVP_CipherInit(ctx->header_evp, ശൂന്യ, ശൂന്യ, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	എങ്കിൽ (!EVP_CipherInit(ctx->main_evp, ശൂന്യ, ശൂന്യ, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}

	/* If encrypting, calculate and append tag */
	എങ്കിൽ (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_താക്കോൽ);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, വലുപ്പം(expected_tag));
	explicit_bzero(seqbuf, വലുപ്പം(seqbuf));
	explicit_bzero(poly_താക്കോൽ, വലുപ്പം(poly_താക്കോൽ));
	തിരികെ r;
}

/* Decrypt and extract the encrypted packet length */
പൂർണ്ണസംഖ്യ
chachapoly_get_length(ഘടന chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, സ്ഥിരം u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	എങ്കിൽ (len < 4)
		തിരികെ SSH_ERR_MESSAGE_INCOMPLETE;
	memset(seqbuf, 0, വലുപ്പം(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	എങ്കിൽ (!EVP_CipherInit(ctx->header_evp, ശൂന്യ, ശൂന്യ, seqbuf, 0))
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	എങ്കിൽ (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, വലുപ്പം(buf)) < 0)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	തിരികെ 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
