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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
ಪೂರ್ಣಾಙ್ಕ
EVP_CIPHER_CTX_get_iv(ಧ್ರುವ EVP_CIPHER_CTX *ctx, unsigned ವರ್ಣ *iv, size_t len)
{
	ಯದಿ (ctx == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (len > EVP_MAX_IV_LENGTH)
		ಪ್ರತ್ಯಾಗಮ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ಯದಿ (len != 0) {
		ಯದಿ (iv == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		memcpy(iv, EVP_CIPHER_CTX_iv(ctx), len);
# ಅನ್ಯಥಾ
		memcpy(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	ಪ್ರತ್ಯಾಗಮ 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
ಪೂರ್ಣಾಙ್ಕ
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, ಧ್ರುವ unsigned ವರ್ಣ *iv, size_t len)
{
	ಯದಿ (ctx == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (len > EVP_MAX_IV_LENGTH)
		ಪ್ರತ್ಯಾಗಮ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ಯದಿ (len != 0) {
		ಯದಿ (iv == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# ಅನ್ಯಥಾ
		memcpy(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	ಪ್ರತ್ಯಾಗಮ 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
