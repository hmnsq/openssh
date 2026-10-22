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

#अन्तर्भाव "includes.h"
#ifdef WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#endif

#जइ !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdarg.h> /* needed for log.h */
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdio.h>  /* needed for misc.h */

#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "cipher-chachapoly.h"

संरचना chachapoly_ctx {
	संरचना chacha_ctx main_ctx, header_ctx;
};

संरचना chachapoly_ctx *
chachapoly_new(ध्रुव u_char *कुञ्चिका, u_int keylen)
{
	संरचना chachapoly_ctx *ctx;

	जइ (keylen != (32 + 32)) /* 2 x 256 bit keys */
		प्रत्यागम रिक्त;
	जइ ((ctx = calloc(1, परिमाण(*ctx))) == रिक्त)
		प्रत्यागम रिक्त;
	chacha_keysetup(&ctx->main_ctx, कुञ्चिका, 256);
	chacha_keysetup(&ctx->header_ctx, कुञ्चिका + 32, 256);
	प्रत्यागम ctx;
}

शून्य
chachapoly_free(संरचना chachapoly_ctx *cpctx)
{
	freezero(cpctx, परिमाण(*cpctx));
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
पूर्णाङ्क
chachapoly_crypt(संरचना chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    ध्रुव u_char *src, u_int len, u_int aadlen, u_int authlen, पूर्णाङ्क do_encrypt)
{
	u_char seqbuf[8];
	ध्रुव u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_कुञ्चिका[POLY1305_KEYLEN];
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_कुञ्चिका, 0, परिमाण(poly_कुञ्चिका));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, रिक्त);
	chacha_encrypt_bytes(&ctx->main_ctx,
	    poly_कुञ्चिका, poly_कुञ्चिका, परिमाण(poly_कुञ्चिका));

	/* If decrypting, check tag before anything else */
	जइ (!do_encrypt) {
		ध्रुव u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_कुञ्चिका);
		जइ (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			गच्छ out;
		}
	}

	/* Crypt additional data */
	जइ (aadlen) {
		chacha_ivsetup(&ctx->header_ctx, seqbuf, रिक्त);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	}

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

	/* If encrypting, calculate and append tag */
	जइ (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_कुञ्चिका);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, परिमाण(expected_tag));
	explicit_bzero(seqbuf, परिमाण(seqbuf));
	explicit_bzero(poly_कुञ्चिका, परिमाण(poly_कुञ्चिका));
	प्रत्यागम r;
}

/* Decrypt and extract the encrypted packet length */
पूर्णाङ्क
chachapoly_get_length(संरचना chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ध्रुव u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[8];

	जइ (len < 4)
		प्रत्यागम SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, रिक्त);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	प्रत्यागम 0;
}

#endif /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
