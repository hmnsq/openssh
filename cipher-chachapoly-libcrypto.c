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

#شامل "includes.h"
#اگر_تعریف_شدہ WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"
#اگر_ختم

#اگر defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#شامل <sys/types.h>
#شامل <string.h>
#شامل <stdio.h>  /* needed for misc.h */

#شامل <openssl/evp.h>

#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "cipher-chachapoly.h"

ساخت chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *سرخی_evp;
};

ساخت chachapoly_ctx *
chachapoly_new(ثابت u_char *کلید, u_int keylen)
{
	ساخت chachapoly_ctx *ctx;

	اگر (keylen != (32 + 32)) /* 2 x 256 bit keys */
		واپس تہی;
	اگر ((ctx = صفر_حافظہ_دو(1, حجم(*ctx))) == تہی)
		واپس تہی;
	اگر ((ctx->main_evp = EVP_CIPHER_CTX_new()) == تہی ||
	    (ctx->سرخی_evp = EVP_CIPHER_CTX_new()) == تہی)
		جاؤ fail;
	اگر (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), کلید, تہی, 1))
		جاؤ fail;
	اگر (!EVP_CipherInit(ctx->سرخی_evp, EVP_chacha20(), کلید + 32, تہی, 1))
		جاؤ fail;
	اگر (EVP_CIPHER_CTX_iv_لمبائی(ctx->سرخی_evp) != 16)
		جاؤ fail;
	واپس ctx;
 fail:
	chachapoly_free(ctx);
	واپس تہی;
}

خالی
chachapoly_free(ساخت chachapoly_ctx *cpctx)
{
	اگر (cpctx == تہی)
		واپس;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->سرخی_evp);
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
صحیح
chachapoly_crypt(ساخت chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ثابت u_char *src, u_int len, u_int aadlen, u_int authlen, صحیح do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	صحیح r = SSH_ERR_اندرونی_ERROR;
	u_char expected_لیبل[POLY1305_TAGLEN], poly_کلید[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, حجم(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_کلید, 0, حجم(poly_کلید));
	اگر (!EVP_CipherInit(ctx->main_evp, تہی, تہی, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_کلید,
	    poly_کلید, حجم(poly_کلید)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}

	/* If decrypting, check tag before anything else */
	اگر (!do_encrypt) {
		ثابت u_char *لیبل = src + aadlen + len;

		poly1305_auth(expected_لیبل, src, aadlen + len, poly_کلید);
		اگر (timingsafe_bcmp(expected_لیبل, لیبل, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			جاؤ برآمد;
		}
	}

	/* Crypt additional data */
	اگر (aadlen) {
		اگر (!EVP_CipherInit(ctx->سرخی_evp, تہی, تہی, seqbuf, 1) ||
		    EVP_Cipher(ctx->سرخی_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	اگر (!EVP_CipherInit(ctx->main_evp, تہی, تہی, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}

	/* If encrypting, calculate and append tag */
	اگر (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_کلید);
	}
	r = 0;
 برآمد:
	explicit_bzero(expected_لیبل, حجم(expected_لیبل));
	explicit_bzero(seqbuf, حجم(seqbuf));
	explicit_bzero(poly_کلید, حجم(poly_کلید));
	واپس r;
}

/* Decrypt and extract the encrypted packet length */
صحیح
chachapoly_get_لمبائی(ساخت chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ثابت u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	اگر (len < 4)
		واپس SSH_ERR_پیغام_INCOMPLETE;
	memset(seqbuf, 0, حجم(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	اگر (!EVP_CipherInit(ctx->سرخی_evp, تہی, تہی, seqbuf, 0))
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	اگر (EVP_Cipher(ctx->سرخی_evp, buf, (u_char *)cp, حجم(buf)) < 0)
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	واپس 0;
}
#اگر_ختم /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
