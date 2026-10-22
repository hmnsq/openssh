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

#અન્તર્ભાવ "includes.h"
#ifdef WITH_OPENSSL
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"
#endif

#જો defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdio.h>  /* needed for misc.h */

#અન્તર્ભાવ <openssl/evp.h>

#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "cipher-chachapoly.h"

સંરચના chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
};

સંરચના chachapoly_ctx *
chachapoly_new(અચલ u_char *ચાવી, u_int keylen)
{
	સંરચના chachapoly_ctx *ctx;

	જો (keylen != (32 + 32)) /* 2 x 256 bit keys */
		પાછા ખાલી;
	જો ((ctx = calloc(1, કદ(*ctx))) == ખાલી)
		પાછા ખાલી;
	જો ((ctx->main_evp = EVP_CIPHER_CTX_new()) == ખાલી ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == ખાલી)
		જાઓ fail;
	જો (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), ચાવી, ખાલી, 1))
		જાઓ fail;
	જો (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), ચાવી + 32, ખાલી, 1))
		જાઓ fail;
	જો (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		જાઓ fail;
	પાછા ctx;
 fail:
	chachapoly_free(ctx);
	પાછા ખાલી;
}

શૂન્ય
chachapoly_free(સંરચના chachapoly_ctx *cpctx)
{
	જો (cpctx == ખાલી)
		પાછા;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, કદ(*cpctx));
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
પૂર્ણાંક
chachapoly_crypt(સંરચના chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    અચલ u_char *src, u_int len, u_int aadlen, u_int authlen, પૂર્ણાંક do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_ચાવી[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, કદ(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_ચાવી, 0, કદ(poly_ચાવી));
	જો (!EVP_CipherInit(ctx->main_evp, ખાલી, ખાલી, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_ચાવી,
	    poly_ચાવી, કદ(poly_ચાવી)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}

	/* If decrypting, check tag before anything else */
	જો (!do_encrypt) {
		અચલ u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_ચાવી);
		જો (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			જાઓ out;
		}
	}

	/* Crypt additional data */
	જો (aadlen) {
		જો (!EVP_CipherInit(ctx->header_evp, ખાલી, ખાલી, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
	}

	/* Set Chacha's block counter to 1 */
	seqbuf[0] = 1;
	જો (!EVP_CipherInit(ctx->main_evp, ખાલી, ખાલી, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}

	/* If encrypting, calculate and append tag */
	જો (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_ચાવી);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, કદ(expected_tag));
	explicit_bzero(seqbuf, કદ(seqbuf));
	explicit_bzero(poly_ચાવી, કદ(poly_ચાવી));
	પાછા r;
}

/* Decrypt and extract the encrypted packet length */
પૂર્ણાંક
chachapoly_get_length(સંરચના chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, અચલ u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	જો (len < 4)
		પાછા SSH_ERR_MESSAGE_INCOMPLETE;
	memset(seqbuf, 0, કદ(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	જો (!EVP_CipherInit(ctx->header_evp, ખાલી, ખાલી, seqbuf, 0))
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	જો (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, કદ(buf)) < 0)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	પાછા 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
