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

#شامل "includes.h"
#ifdef WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"
#endif

#اگر !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#شامل <sys/types.h>
#شامل <stdarg.h> /* needed for log.h */
#شامل <string.h>
#شامل <stdio.h>  /* needed for misc.h */

#شامل "log.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "cipher-chachapoly.h"

ساختار chachapoly_ctx {
	ساختار chacha_ctx main_ctx, header_ctx;
};

ساختار chachapoly_ctx *
chachapoly_new(ثابت u_char *کلید, u_int keylen)
{
	ساختار chachapoly_ctx *ctx;

	اگر (keylen != (32 + 32)) /* 2 x 256 bit keys */
		بازگشت پوچ;
	اگر ((ctx = calloc(1, اندازه(*ctx))) == پوچ)
		بازگشت پوچ;
	chacha_keysetup(&ctx->main_ctx, کلید, 256);
	chacha_keysetup(&ctx->header_ctx, کلید + 32, 256);
	بازگشت ctx;
}

تهی
chachapoly_free(ساختار chachapoly_ctx *cpctx)
{
	freezero(cpctx, اندازه(*cpctx));
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
chachapoly_crypt(ساختار chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ثابت u_char *src, u_int len, u_int aadlen, u_int authlen, صحیح do_encrypt)
{
	u_char seqbuf[8];
	ثابت u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_کلید[POLY1305_KEYLEN];
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_کلید, 0, اندازه(poly_کلید));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, پوچ);
	chacha_encrypt_bytes(&ctx->main_ctx,
	    poly_کلید, poly_کلید, اندازه(poly_کلید));

	/* If decrypting, check tag before anything else */
	اگر (!do_encrypt) {
		ثابت u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_کلید);
		اگر (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			برو out;
		}
	}

	/* Crypt additional data */
	اگر (aadlen) {
		chacha_ivsetup(&ctx->header_ctx, seqbuf, پوچ);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	}

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

	/* If encrypting, calculate and append tag */
	اگر (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_کلید);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, اندازه(expected_tag));
	explicit_bzero(seqbuf, اندازه(seqbuf));
	explicit_bzero(poly_کلید, اندازه(poly_کلید));
	بازگشت r;
}

/* Decrypt and extract the encrypted packet length */
صحیح
chachapoly_get_length(ساختار chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ثابت u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[8];

	اگر (len < 4)
		بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, پوچ);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	بازگشت 0;
}

#endif /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
