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

#అన్తర్భావ "includes.h"
#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ "openbsd-compat/openssl-compat.h"
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdio.h>  /* needed for misc.h */

#అన్తర్భావ <openssl/evp.h>

#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "cipher-chachapoly.h"

నిర్మాణం chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *శీర్షిక_evp;
};

నిర్మాణం chachapoly_ctx *
chachapoly_new(స్థిరరాశి u_char *కీలకం, u_int keylen)
{
	నిర్మాణం chachapoly_ctx *ctx;

	ఒకవేళ (keylen != (32 + 32)) /* 2 x 256 bit keys */
		తిరిగి ఖాళీ;
	ఒకవేళ ((ctx = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ctx))) == ఖాళీ)
		తిరిగి ఖాళీ;
	ఒకవేళ ((ctx->main_evp = EVP_CIPHER_CTX_new()) == ఖాళీ ||
	    (ctx->శీర్షిక_evp = EVP_CIPHER_CTX_new()) == ఖాళీ)
		వెళ్ళు fail;
	ఒకవేళ (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), కీలకం, ఖాళీ, 1))
		వెళ్ళు fail;
	ఒకవేళ (!EVP_CipherInit(ctx->శీర్షిక_evp, EVP_chacha20(), కీలకం + 32, ఖాళీ, 1))
		వెళ్ళు fail;
	ఒకవేళ (EVP_CIPHER_CTX_iv_నిడివి(ctx->శీర్షిక_evp) != 16)
		వెళ్ళు fail;
	తిరిగి ctx;
 fail:
	chachapoly_free(ctx);
	తిరిగి ఖాళీ;
}

శూన్య
chachapoly_free(నిర్మాణం chachapoly_ctx *cpctx)
{
	ఒకవేళ (cpctx == ఖాళీ)
		తిరిగి;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->శీర్షిక_evp);
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
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	u_char expected_ట్యాగ్[POLY1305_TAGLEN], poly_కీలకం[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, పరిమాణం(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_కీలకం, 0, పరిమాణం(poly_కీలకం));
	ఒకవేళ (!EVP_CipherInit(ctx->main_evp, ఖాళీ, ఖాళీ, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_కీలకం,
	    poly_కీలకం, పరిమాణం(poly_కీలకం)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}

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
		ఒకవేళ (!EVP_CipherInit(ctx->శీర్షిక_evp, ఖాళీ, ఖాళీ, seqbuf, 1) ||
		    EVP_Cipher(ctx->శీర్షిక_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	ఒకవేళ (!EVP_CipherInit(ctx->main_evp, ఖాళీ, ఖాళీ, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}

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
	u_char buf[4], seqbuf[16];

	ఒకవేళ (len < 4)
		తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	memset(seqbuf, 0, పరిమాణం(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	ఒకవేళ (!EVP_CipherInit(ctx->శీర్షిక_evp, ఖాళీ, ఖాళీ, seqbuf, 0))
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	ఒకవేళ (EVP_Cipher(ctx->శీర్షిక_evp, buf, (u_char *)cp, పరిమాణం(buf)) < 0)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	తిరిగి 0;
}
#అయితే_ముగింపు /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
