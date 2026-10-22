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

#include "includes.h"
#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#endif

#නම් defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include <openssl/evp.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"

sa_nracanaa chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

sa_nracanaa chachapoly_ctx *
chachapoly_new(const u_char *key, u_int keylen)
{
	sa_nracanaa chachapoly_ctx *ctx;

	නම් (keylen != (32 + 32)) /* 2 x 256 bit keys */
		ආපසු NULL;
	නම් ((ctx = calloc(1, parimaa_na(*ctx))) == NULL)
		ආපසු NULL;
	නම් ((ctx->main_evp = EVP_CIPHER_CTX_new()) == NULL ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == NULL)
		goto fail;
	නම් (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), key, NULL, 1))
		goto fail;
	නම් (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), key + 32, NULL, 1))
		goto fail;
	නම් (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		goto fail;
	ආපසු ctx;
 fail:
	chachapoly_free(ctx);
	ආපසු NULL;
}

void
chachapoly_free(sa_nracanaa chachapoly_ctx *cpctx)
{
	නම් (cpctx == NULL)
		ආපසු;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, parimaa_na(*cpctx));
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
පූර්ණ_සංඛ්‍යා
chachapoly_crypt(sa_nracanaa chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, පූර්ණ_සංඛ්‍යා do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	පූර්ණ_සංඛ්‍යා r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, parimaa_na(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_key, 0, parimaa_na(poly_key));
	නම් (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_key,
	    poly_key, parimaa_na(poly_key)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* If decrypting, check tag before anything else */
	නම් (!do_encrypt) {
		const u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_key);
		නම් (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			goto out;
		}
	}

	/* Crypt additional data */
	නම් (aadlen) {
		නම් (!EVP_CipherInit(ctx->header_evp, NULL, NULL, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	නම් (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* If encrypting, calculate and append tag */
	නම් (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_key);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, parimaa_na(expected_tag));
	explicit_bzero(seqbuf, parimaa_na(seqbuf));
	explicit_bzero(poly_key, parimaa_na(poly_key));
	ආපසු r;
}

/* Decrypt and extract the encrypted packet length */
පූර්ණ_සංඛ්‍යා
chachapoly_get_length(sa_nracanaa chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	නම් (len < 4)
		ආපසු SSH_ERR_MESSAGE_INCOMPLETE;
	memset(seqbuf, 0, parimaa_na(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	නම් (!EVP_CipherInit(ctx->header_evp, NULL, NULL, seqbuf, 0))
		ආපසු SSH_ERR_LIBCRYPTO_ERROR;
	නම් (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, parimaa_na(buf)) < 0)
		ආපසු SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	ආපසු 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
