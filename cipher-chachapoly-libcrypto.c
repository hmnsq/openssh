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

#অন্তর্ভাৱ "includes.h"
#ifdef WITH_OPENSSL
#অন্তর্ভাৱ "openbsd-compat/openssl-compat.h"
#endif

#যদি defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdio.h>  /* needed for misc.h */

#অন্তর্ভাৱ <openssl/evp.h>

#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "cipher-chachapoly.h"

সংরচনা chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

সংরচনা chachapoly_ctx *
chachapoly_new(ধ্রুৱ u_char *চাবি, u_int keylen)
{
	সংরচনা chachapoly_ctx *ctx;

	যদি (keylen != (32 + 32)) /* 2 x 256 bit keys */
		ঘূৰাই রিক্ত;
	যদি ((ctx = calloc(1, পরিমাণ(*ctx))) == রিক্ত)
		ঘূৰাই রিক্ত;
	যদি ((ctx->main_evp = EVP_CIPHER_CTX_new()) == রিক্ত ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == রিক্ত)
		গচ্ছ fail;
	যদি (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), চাবি, রিক্ত, 1))
		গচ্ছ fail;
	যদি (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), চাবি + 32, রিক্ত, 1))
		গচ্ছ fail;
	যদি (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		গচ্ছ fail;
	ঘূৰাই ctx;
 fail:
	chachapoly_free(ctx);
	ঘূৰাই রিক্ত;
}

শূন্য
chachapoly_free(সংরচনা chachapoly_ctx *cpctx)
{
	যদি (cpctx == রিক্ত)
		ঘূৰাই;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, পরিমাণ(*cpctx));
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
পূর্ণাঙ্ক
chachapoly_crypt(সংরচনা chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ধ্রুৱ u_char *src, u_int len, u_int aadlen, u_int authlen, পূর্ণাঙ্ক do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_চাবি[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, পরিমাণ(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_চাবি, 0, পরিমাণ(poly_চাবি));
	যদি (!EVP_CipherInit(ctx->main_evp, রিক্ত, রিক্ত, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_চাবি,
	    poly_চাবি, পরিমাণ(poly_চাবি)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}

	/* If decrypting, check tag before anything else */
	যদি (!do_encrypt) {
		ধ্রুৱ u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_চাবি);
		যদি (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			গচ্ছ out;
		}
	}

	/* Crypt additional data */
	যদি (aadlen) {
		যদি (!EVP_CipherInit(ctx->header_evp, রিক্ত, রিক্ত, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			গচ্ছ out;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	যদি (!EVP_CipherInit(ctx->main_evp, রিক্ত, রিক্ত, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}

	/* If encrypting, calculate and append tag */
	যদি (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_চাবি);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, পরিমাণ(expected_tag));
	explicit_bzero(seqbuf, পরিমাণ(seqbuf));
	explicit_bzero(poly_চাবি, পরিমাণ(poly_চাবি));
	ঘূৰাই r;
}

/* Decrypt and extract the encrypted packet length */
পূর্ণাঙ্ক
chachapoly_get_length(সংরচনা chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ধ্রুৱ u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	যদি (len < 4)
		ঘূৰাই SSH_ERR_MESSAGE_INCOMPLETE;
	memset(seqbuf, 0, পরিমাণ(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	যদি (!EVP_CipherInit(ctx->header_evp, রিক্ত, রিক্ত, seqbuf, 0))
		ঘূৰাই SSH_ERR_LIBCRYPTO_ERROR;
	যদি (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, পরিমাণ(buf)) < 0)
		ঘূৰাই SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	ঘূৰাই 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
