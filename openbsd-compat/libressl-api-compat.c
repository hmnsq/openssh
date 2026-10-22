/*
 * Copyright (c) 2018 Damien Miller <djm@mindrot.org>
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

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ <openssl/evp.h>

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
પૂર્ણાંક
EVP_CIPHER_CTX_get_iv(અચલ EVP_CIPHER_CTX *ctx, unsigned અક્ષર *iv, size_t len)
{
	જો (ctx == ખાલી)
		પાછા 0;
	જો (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		પાછા 0;
	જો (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		પાછા 0;
	જો (len > EVP_MAX_IV_LENGTH)
		પાછા 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	જો (len != 0) {
		જો (iv == ખાલી)
			પાછા 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		memcpy(iv, EVP_CIPHER_CTX_iv(ctx), len);
# નહીંતર
		memcpy(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	પાછા 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
પૂર્ણાંક
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, અચલ unsigned અક્ષર *iv, size_t len)
{
	જો (ctx == ખાલી)
		પાછા 0;
	જો (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		પાછા 0;
	જો (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		પાછા 0;
	જો (len > EVP_MAX_IV_LENGTH)
		પાછા 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	જો (len != 0) {
		જો (iv == ખાલી)
			પાછા 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# નહીંતર
		memcpy(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	પાછા 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
