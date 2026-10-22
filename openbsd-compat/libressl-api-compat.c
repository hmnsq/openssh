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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_EVP_CIPHER_CTX_GET_IV
ಪೂರ್ಣಾಂಕ
EVP_CIPHER_CTX_get_iv(ಸ್ಥಿರಾಂಕ EVP_CIPHER_CTX *ctx, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *iv, ಗಾತ್ರ_t len)
{
	ಆದರೆ (ctx == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (EVP_CIPHER_CTX_iv_ಉದ್ದಳತೆ(ctx) < 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (len != (ಗಾತ್ರ_t)EVP_CIPHER_CTX_iv_ಉದ್ದಳತೆ(ctx))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (len > EVP_MAX_IV_ಉದ್ದಳತೆ)
		ಹಿಂತಿರುಗಿ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ಆದರೆ (len != 0) {
		ಆದರೆ (iv == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		ಸ್ಮರಣೆ_ನಕಲು(iv, EVP_CIPHER_CTX_iv(ctx), len);
# ಇಲ್ಲದಿದ್ದರೆ
		ಸ್ಮರಣೆ_ನಕಲು(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	ಹಿಂತಿರುಗಿ 1;
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_EVP_CIPHER_CTX_ಗಣ_IV
ಪೂರ್ಣಾಂಕ
EVP_CIPHER_CTX_ಗಣ_iv(EVP_CIPHER_CTX *ctx, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *iv, ಗಾತ್ರ_t len)
{
	ಆದರೆ (ctx == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (EVP_CIPHER_CTX_iv_ಉದ್ದಳತೆ(ctx) < 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (len != (ಗಾತ್ರ_t)EVP_CIPHER_CTX_iv_ಉದ್ದಳತೆ(ctx))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (len > EVP_MAX_IV_ಉದ್ದಳತೆ)
		ಹಿಂತಿರುಗಿ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ಆದರೆ (len != 0) {
		ಆದರೆ (iv == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		ಸ್ಮರಣೆ_ನಕಲು(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# ಇಲ್ಲದಿದ್ದರೆ
		ಸ್ಮರಣೆ_ನಕಲು(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	ಹಿಂತಿರುಗಿ 1;
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_EVP_CIPHER_CTX_SET_IV */

#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
