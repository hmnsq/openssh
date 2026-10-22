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

#অন্তর্ভাব "includes.h"
#ifdef WITH_OPENSSL
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"
#endif

#যদি !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdarg.h> /* needed for log.h */
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdio.h>  /* needed for misc.h */

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "cipher-chachapoly.h"

সংরচনা chachapoly_ctx {
	সংরচনা chacha_ctx main_ctx, header_ctx;
};

সংরচনা chachapoly_ctx *
chachapoly_new(ধ্রুব u_char *চাবি, u_int keylen)
{
	সংরচনা chachapoly_ctx *ctx;

	যদি (keylen != (32 + 32)) /* 2 x 256 bit keys */
		প্রত্যাগম রিক্ত;
	যদি ((ctx = calloc(1, পরিমাণ(*ctx))) == রিক্ত)
		প্রত্যাগম রিক্ত;
	chacha_keysetup(&ctx->main_ctx, চাবি, 256);
	chacha_keysetup(&ctx->header_ctx, চাবি + 32, 256);
	প্রত্যাগম ctx;
}

শূন্য
chachapoly_free(সংরচনা chachapoly_ctx *cpctx)
{
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
    ধ্রুব u_char *src, u_int len, u_int aadlen, u_int authlen, পূর্ণাঙ্ক do_encrypt)
{
	u_char seqbuf[8];
	ধ্রুব u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_চাবি[POLY1305_KEYLEN];
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_চাবি, 0, পরিমাণ(poly_চাবি));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, রিক্ত);
	chacha_encrypt_bytes(&ctx->main_ctx,
	    poly_চাবি, poly_চাবি, পরিমাণ(poly_চাবি));

	/* If decrypting, check tag before anything else */
	যদি (!do_encrypt) {
		ধ্রুব u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_চাবি);
		যদি (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			গচ্ছ out;
		}
	}

	/* Crypt additional data */
	যদি (aadlen) {
		chacha_ivsetup(&ctx->header_ctx, seqbuf, রিক্ত);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	}

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

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
	প্রত্যাগম r;
}

/* Decrypt and extract the encrypted packet length */
পূর্ণাঙ্ক
chachapoly_get_length(সংরচনা chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, ধ্রুব u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[8];

	যদি (len < 4)
		প্রত্যাগম SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, রিক্ত);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	প্রত্যাগম 0;
}

#endif /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
