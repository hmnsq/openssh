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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"
#ਜੇ_ਅੰਤ

#ਜੇ !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h> /* needed for log.h */
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>  /* needed for misc.h */

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher-chachapoly.h"

ਬਣਤਰ chachapoly_ctx {
	ਬਣਤਰ chacha_ctx main_ctx, ਸਿਰਲੇਖ_ctx;
};

ਬਣਤਰ chachapoly_ctx *
chachapoly_new(ਅਚਲ u_char *ਕੁੰਜੀ, u_int keylen)
{
	ਬਣਤਰ chachapoly_ctx *ctx;

	ਜੇ (keylen != (32 + 32)) /* 2 x 256 bit keys */
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ ((ctx = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ctx))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	chacha_keysetup(&ctx->main_ctx, ਕੁੰਜੀ, 256);
	chacha_keysetup(&ctx->ਸਿਰਲੇਖ_ctx, ਕੁੰਜੀ + 32, 256);
	ਵਾਪਸ ctx;
}

ਖਾਲੀ
chachapoly_free(ਬਣਤਰ chachapoly_ctx *cpctx)
{
	freezero(cpctx, ਆਕਾਰ(*cpctx));
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
ਪੂਰਨ
chachapoly_crypt(ਬਣਤਰ chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ਅਚਲ u_char *src, u_int len, u_int aadlen, u_int authlen, ਪੂਰਨ do_encrypt)
{
	u_char seqbuf[8];
	ਅਚਲ u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_ਟੈਗ[POLY1305_TAGLEN], poly_ਕੁੰਜੀ[POLY1305_KEYLEN];
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_ਕੁੰਜੀ, 0, ਆਕਾਰ(poly_ਕੁੰਜੀ));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, ਨਿਰਾ);
	chacha_encrypt_ਬਾਈਟਾਂ(&ctx->main_ctx,
	    poly_ਕੁੰਜੀ, poly_ਕੁੰਜੀ, ਆਕਾਰ(poly_ਕੁੰਜੀ));

	/* If decrypting, check tag before anything else */
	ਜੇ (!do_encrypt) {
		ਅਚਲ u_char *ਟੈਗ = src + aadlen + len;

		poly1305_auth(expected_ਟੈਗ, src, aadlen + len, poly_ਕੁੰਜੀ);
		ਜੇ (timingsafe_bcmp(expected_ਟੈਗ, ਟੈਗ, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	/* Crypt additional data */
	ਜੇ (aadlen) {
		chacha_ivsetup(&ctx->ਸਿਰਲੇਖ_ctx, seqbuf, ਨਿਰਾ);
		chacha_encrypt_ਬਾਈਟਾਂ(&ctx->ਸਿਰਲੇਖ_ctx, src, dest, aadlen);
	}

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_ਬਾਈਟਾਂ(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

	/* If encrypting, calculate and append tag */
	ਜੇ (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_ਕੁੰਜੀ);
	}
	r = 0;
 ਬਾਹਰਲਾ:
	explicit_bzero(expected_ਟੈਗ, ਆਕਾਰ(expected_ਟੈਗ));
	explicit_bzero(seqbuf, ਆਕਾਰ(seqbuf));
	explicit_bzero(poly_ਕੁੰਜੀ, ਆਕਾਰ(poly_ਕੁੰਜੀ));
	ਵਾਪਸ r;
}

/* Decrypt and extract the encrypted packet length */
ਪੂਰਨ
chachapoly_get_ਲੰਮਾਈ(ਬਣਤਰ chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ਅਚਲ u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[8];

	ਜੇ (len < 4)
		ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->ਸਿਰਲੇਖ_ctx, seqbuf, ਨਿਰਾ);
	chacha_encrypt_ਬਾਈਟਾਂ(&ctx->ਸਿਰਲੇਖ_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	ਵਾਪਸ 0;
}

#ਜੇ_ਅੰਤ /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
