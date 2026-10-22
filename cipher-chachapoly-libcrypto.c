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

#ضمن "includes.h"
#ifdef WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"
#endif

#אם defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#ضمن <sys/types.h>
#ضمن <string.h>
#ضمن <stdio.h>  /* needed for misc.h */

#ضمن <openssl/evp.h>

#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "cipher-chachapoly.h"

بنية chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

بنية chachapoly_ctx *
chachapoly_new(ثابت u_char *key, u_int keylen)
{
	بنية chachapoly_ctx *ctx;

	אם (keylen != (32 + 32)) /* 2 x 256 bit keys */
		החזר عدم;
	אם ((ctx = calloc(1, حجم(*ctx))) == عدم)
		החזר عدم;
	אם ((ctx->main_evp = EVP_CIPHER_CTX_new()) == عدم ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == عدم)
		اذهب fail;
	אם (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), key, عدم, 1))
		اذهب fail;
	אם (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), key + 32, عدم, 1))
		اذهب fail;
	אם (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		اذهب fail;
	החזר ctx;
 fail:
	chachapoly_free(ctx);
	החזר عدم;
}

فراغ
chachapoly_free(بنية chachapoly_ctx *cpctx)
{
	אם (cpctx == عدم)
		החזר;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, حجم(*cpctx));
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
صحيح
chachapoly_crypt(بنية chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ثابت u_char *src, u_int len, u_int aadlen, u_int authlen, صحيح do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, حجم(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_key, 0, حجم(poly_key));
	אם (!EVP_CipherInit(ctx->main_evp, عدم, عدم, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_key,
	    poly_key, حجم(poly_key)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}

	/* If decrypting, check tag before anything else */
	אם (!do_encrypt) {
		ثابت u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_key);
		אם (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			اذهب out;
		}
	}

	/* Crypt additional data */
	אם (aadlen) {
		אם (!EVP_CipherInit(ctx->header_evp, عدم, عدم, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	אם (!EVP_CipherInit(ctx->main_evp, عدم, عدم, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}

	/* If encrypting, calculate and append tag */
	אם (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_key);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, حجم(expected_tag));
	explicit_bzero(seqbuf, حجم(seqbuf));
	explicit_bzero(poly_key, حجم(poly_key));
	החזר r;
}

/* Decrypt and extract the encrypted packet length */
صحيح
chachapoly_get_length(بنية chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ثابت u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	אם (len < 4)
		החזר SSH_ERR_MESSAGE_INCOMPLETE;
	memset(seqbuf, 0, حجم(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	אם (!EVP_CipherInit(ctx->header_evp, عدم, عدم, seqbuf, 0))
		החזר SSH_ERR_LIBCRYPTO_ERROR;
	אם (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, حجم(buf)) < 0)
		החזר SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	החזר 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
