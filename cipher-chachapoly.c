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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#endif

#ಯದಿ !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h> /* needed for log.h */
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>  /* needed for misc.h */

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "cipher-chachapoly.h"

ಸಂರಚನಾ chachapoly_ctx {
	ಸಂರಚನಾ chacha_ctx main_ctx, header_ctx;
};

ಸಂರಚನಾ chachapoly_ctx *
chachapoly_new(ಧ್ರುವ u_char *ಕೀಲಿ, u_int keylen)
{
	ಸಂರಚನಾ chachapoly_ctx *ctx;

	ಯದಿ (keylen != (32 + 32)) /* 2 x 256 bit keys */
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ ((ctx = calloc(1, ಪರಿಮಾಣ(*ctx))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	chacha_keysetup(&ctx->main_ctx, ಕೀಲಿ, 256);
	chacha_keysetup(&ctx->header_ctx, ಕೀಲಿ + 32, 256);
	ಪ್ರತ್ಯಾಗಮ ctx;
}

ಶೂನ್ಯ
chachapoly_free(ಸಂರಚನಾ chachapoly_ctx *cpctx)
{
	freezero(cpctx, ಪರಿಮಾಣ(*cpctx));
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
ಪೂರ್ಣಾಙ್ಕ
chachapoly_crypt(ಸಂರಚನಾ chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ಧ್ರುವ u_char *src, u_int len, u_int aadlen, u_int authlen, ಪೂರ್ಣಾಙ್ಕ do_encrypt)
{
	u_char seqbuf[8];
	ಧ್ರುವ u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_ಕೀಲಿ[POLY1305_KEYLEN];
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_ಕೀಲಿ, 0, ಪರಿಮಾಣ(poly_ಕೀಲಿ));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, ರಿಕ್ತ);
	chacha_encrypt_bytes(&ctx->main_ctx,
	    poly_ಕೀಲಿ, poly_ಕೀಲಿ, ಪರಿಮಾಣ(poly_ಕೀಲಿ));

	/* If decrypting, check tag before anything else */
	ಯದಿ (!do_encrypt) {
		ಧ್ರುವ u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_ಕೀಲಿ);
		ಯದಿ (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			ಗಚ್ಛ out;
		}
	}

	/* Crypt additional data */
	ಯದಿ (aadlen) {
		chacha_ivsetup(&ctx->header_ctx, seqbuf, ರಿಕ್ತ);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	}

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

	/* If encrypting, calculate and append tag */
	ಯದಿ (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_ಕೀಲಿ);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, ಪರಿಮಾಣ(expected_tag));
	explicit_bzero(seqbuf, ಪರಿಮಾಣ(seqbuf));
	explicit_bzero(poly_ಕೀಲಿ, ಪರಿಮಾಣ(poly_ಕೀಲಿ));
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Decrypt and extract the encrypted packet length */
ಪೂರ್ಣಾಙ್ಕ
chachapoly_get_length(ಸಂರಚನಾ chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ಧ್ರುವ u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[8];

	ಯದಿ (len < 4)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, ರಿಕ್ತ);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	ಪ್ರತ್ಯಾಗಮ 0;
}

#endif /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
