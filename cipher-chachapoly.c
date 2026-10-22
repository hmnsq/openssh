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

#அந்தர்பாவ "includes.h"
#ifdef WITH_OPENSSL
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"
#endif

#எனில் !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdarg.h> /* needed for log.h */
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdio.h>  /* needed for misc.h */

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "cipher-chachapoly.h"

கட்டமைப்பு chachapoly_ctx {
	கட்டமைப்பு chacha_ctx main_ctx, header_ctx;
};

கட்டமைப்பு chachapoly_ctx *
chachapoly_new(மாறிலி u_char *சாவி, u_int keylen)
{
	கட்டமைப்பு chachapoly_ctx *ctx;

	எனில் (keylen != (32 + 32)) /* 2 x 256 bit keys */
		திரும்பு வெற்று;
	எனில் ((ctx = calloc(1, அளவு(*ctx))) == வெற்று)
		திரும்பு வெற்று;
	chacha_keysetup(&ctx->main_ctx, சாவி, 256);
	chacha_keysetup(&ctx->header_ctx, சாவி + 32, 256);
	திரும்பு ctx;
}

வெறுமை
chachapoly_free(கட்டமைப்பு chachapoly_ctx *cpctx)
{
	freezero(cpctx, அளவு(*cpctx));
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
முழு
chachapoly_crypt(கட்டமைப்பு chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    மாறிலி u_char *src, u_int len, u_int aadlen, u_int authlen, முழு do_encrypt)
{
	u_char seqbuf[8];
	மாறிலி u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_சாவி[POLY1305_KEYLEN];
	முழு r = SSH_ERR_INTERNAL_ERROR;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_சாவி, 0, அளவு(poly_சாவி));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, வெற்று);
	chacha_encrypt_bytes(&ctx->main_ctx,
	    poly_சாவி, poly_சாவி, அளவு(poly_சாவி));

	/* If decrypting, check tag before anything else */
	எனில் (!do_encrypt) {
		மாறிலி u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_சாவி);
		எனில் (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			செல் out;
		}
	}

	/* Crypt additional data */
	எனில் (aadlen) {
		chacha_ivsetup(&ctx->header_ctx, seqbuf, வெற்று);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	}

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

	/* If encrypting, calculate and append tag */
	எனில் (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_சாவி);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, அளவு(expected_tag));
	explicit_bzero(seqbuf, அளவு(seqbuf));
	explicit_bzero(poly_சாவி, அளவு(poly_சாவி));
	திரும்பு r;
}

/* Decrypt and extract the encrypted packet length */
முழு
chachapoly_get_length(கட்டமைப்பு chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, மாறிலி u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[8];

	எனில் (len < 4)
		திரும்பு SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, வெற்று);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	திரும்பு 0;
}

#endif /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
