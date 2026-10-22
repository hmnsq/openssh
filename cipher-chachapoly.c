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

#అన్తర్భావ "includes.h"
#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ "openbsd-compat/openssl-compat.h"
#అయితే_ముగింపు

#ఒకవేళ !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdarg.h> /* needed for log.h */
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdio.h>  /* needed for misc.h */

#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "cipher-chachapoly.h"

నిర్మాణం chachapoly_ctx {
	నిర్మాణం chacha_ctx main_ctx, శీర్షిక_ctx;
};

నిర్మాణం chachapoly_ctx *
chachapoly_new(స్థిరరాశి u_char *కీలకం, u_int keylen)
{
	నిర్మాణం chachapoly_ctx *ctx;

	ఒకవేళ (keylen != (32 + 32)) /* 2 x 256 bit keys */
		తిరిగి ఖాళీ;
	ఒకవేళ ((ctx = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ctx))) == ఖాళీ)
		తిరిగి ఖాళీ;
	chacha_keysetup(&ctx->main_ctx, కీలకం, 256);
	chacha_keysetup(&ctx->శీర్షిక_ctx, కీలకం + 32, 256);
	తిరిగి ctx;
}

శూన్య
chachapoly_free(నిర్మాణం chachapoly_ctx *cpctx)
{
	freezero(cpctx, పరిమాణం(*cpctx));
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
పూర్ణాంకం
chachapoly_crypt(నిర్మాణం chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    స్థిరరాశి u_char *src, u_int len, u_int aadlen, u_int authlen, పూర్ణాంకం do_encrypt)
{
	u_char seqbuf[8];
	స్థిరరాశి u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_ట్యాగ్[POLY1305_TAGLEN], poly_కీలకం[POLY1305_KEYLEN];
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_కీలకం, 0, పరిమాణం(poly_కీలకం));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, ఖాళీ);
	chacha_encrypt_బైట్లు(&ctx->main_ctx,
	    poly_కీలకం, poly_కీలకం, పరిమాణం(poly_కీలకం));

	/* If decrypting, check tag before anything else */
	ఒకవేళ (!do_encrypt) {
		స్థిరరాశి u_char *ట్యాగ్ = src + aadlen + len;

		poly1305_auth(expected_ట్యాగ్, src, aadlen + len, poly_కీలకం);
		ఒకవేళ (timingsafe_bcmp(expected_ట్యాగ్, ట్యాగ్, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			వెళ్ళు బహిర్గతం;
		}
	}

	/* Crypt additional data */
	ఒకవేళ (aadlen) {
		chacha_ivsetup(&ctx->శీర్షిక_ctx, seqbuf, ఖాళీ);
		chacha_encrypt_బైట్లు(&ctx->శీర్షిక_ctx, src, dest, aadlen);
	}

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
	chacha_encrypt_బైట్లు(&ctx->main_ctx, src + aadlen,
	    dest + aadlen, len);

	/* If encrypting, calculate and append tag */
	ఒకవేళ (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_కీలకం);
	}
	r = 0;
 బహిర్గతం:
	explicit_bzero(expected_ట్యాగ్, పరిమాణం(expected_ట్యాగ్));
	explicit_bzero(seqbuf, పరిమాణం(seqbuf));
	explicit_bzero(poly_కీలకం, పరిమాణం(poly_కీలకం));
	తిరిగి r;
}

/* Decrypt and extract the encrypted packet length */
పూర్ణాంకం
chachapoly_get_నిడివి(నిర్మాణం chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, స్థిరరాశి u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[8];

	ఒకవేళ (len < 4)
		తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->శీర్షిక_ctx, seqbuf, ఖాళీ);
	chacha_encrypt_బైట్లు(&ctx->శీర్షిక_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	తిరిగి 0;
}

#అయితే_ముగింపు /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
