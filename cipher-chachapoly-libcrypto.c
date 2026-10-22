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
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"
#جيڪڏهن_پورو

#إذا defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#ضمن <sys/types.h>
#ضمن <string.h>
#ضمن <stdio.h>  /* needed for misc.h */

#ضمن <openssl/evp.h>

#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "cipher-chachapoly.h"

بنية chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *سرو_evp;
};

بنية chachapoly_ctx *
chachapoly_new(ثابت u_char *ڪنجي, u_int keylen)
{
	بنية chachapoly_ctx *ctx;

	إذا (keylen != (32 + 32)) /* 2 x 256 bit keys */
		أرجع عدم;
	إذا ((ctx = صفر_يادگيري_ڏيو(1, حجم(*ctx))) == عدم)
		أرجع عدم;
	إذا ((ctx->main_evp = EVP_CIPHER_CTX_new()) == عدم ||
	    (ctx->سرو_evp = EVP_CIPHER_CTX_new()) == عدم)
		اذهب fail;
	إذا (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), ڪنجي, عدم, 1))
		اذهب fail;
	إذا (!EVP_CipherInit(ctx->سرو_evp, EVP_chacha20(), ڪنجي + 32, عدم, 1))
		اذهب fail;
	إذا (EVP_CIPHER_CTX_iv_ڊيگهائي(ctx->سرو_evp) != 16)
		اذهب fail;
	أرجع ctx;
 fail:
	chachapoly_free(ctx);
	أرجع عدم;
}

فراغ
chachapoly_free(بنية chachapoly_ctx *cpctx)
{
	إذا (cpctx == عدم)
		أرجع;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->سرو_evp);
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
	صحيح r = SSH_ERR_اندروني_ERROR;
	u_char expected_ٽيگ[POLY1305_TAGLEN], poly_ڪنجي[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, حجم(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_ڪنجي, 0, حجم(poly_ڪنجي));
	إذا (!EVP_CipherInit(ctx->main_evp, عدم, عدم, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_ڪنجي,
	    poly_ڪنجي, حجم(poly_ڪنجي)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}

	/* If decrypting, check tag before anything else */
	إذا (!do_encrypt) {
		ثابت u_char *ٽيگ = src + aadlen + len;

		poly1305_auth(expected_ٽيگ, src, aadlen + len, poly_ڪنجي);
		إذا (timingsafe_bcmp(expected_ٽيگ, ٽيگ, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			اذهب ٻاهريون;
		}
	}

	/* Crypt additional data */
	إذا (aadlen) {
		إذا (!EVP_CipherInit(ctx->سرو_evp, عدم, عدم, seqbuf, 1) ||
		    EVP_Cipher(ctx->سرو_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب ٻاهريون;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	إذا (!EVP_CipherInit(ctx->main_evp, عدم, عدم, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}

	/* If encrypting, calculate and append tag */
	إذا (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_ڪنجي);
	}
	r = 0;
 ٻاهريون:
	explicit_bzero(expected_ٽيگ, حجم(expected_ٽيگ));
	explicit_bzero(seqbuf, حجم(seqbuf));
	explicit_bzero(poly_ڪنجي, حجم(poly_ڪنجي));
	أرجع r;
}

/* Decrypt and extract the encrypted packet length */
صحيح
chachapoly_get_ڊيگهائي(بنية chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ثابت u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	إذا (len < 4)
		أرجع SSH_ERR_پيغام_INCOMPLETE;
	memset(seqbuf, 0, حجم(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	إذا (!EVP_CipherInit(ctx->سرو_evp, عدم, عدم, seqbuf, 0))
		أرجع SSH_ERR_LIBCRYPTO_ERROR;
	إذا (EVP_Cipher(ctx->سرو_evp, buf, (u_char *)cp, حجم(buf)) < 0)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	أرجع 0;
}
#جيڪڏهن_پورو /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
