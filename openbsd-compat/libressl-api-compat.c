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

#شامل "includes.h"

#اگر_تعریف_شدہ WITH_OPENSSL

#شامل <sys/types.h>

#شامل <stdlib.h>
#شامل <string.h>

#شامل <openssl/evp.h>

#اگر_غیر_تعریف_شدہ HAVE_EVP_CIPHER_CTX_GET_IV
صحیح
EVP_CIPHER_CTX_get_iv(ثابت EVP_CIPHER_CTX *ctx, غیرعلامتی حرف *iv, سائز_t len)
{
	اگر (ctx == تہی)
		واپس 0;
	اگر (EVP_CIPHER_CTX_iv_لمبائی(ctx) < 0)
		واپس 0;
	اگر (len != (سائز_t)EVP_CIPHER_CTX_iv_لمبائی(ctx))
		واپس 0;
	اگر (len > EVP_MAX_IV_لمبائی)
		واپس 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	اگر (len != 0) {
		اگر (iv == تہی)
			واپس 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		حافظہ_نقل(iv, EVP_CIPHER_CTX_iv(ctx), len);
# ورنہ
		حافظہ_نقل(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	واپس 1;
}
#اگر_ختم /* HAVE_EVP_CIPHER_CTX_GET_IV */

#اگر_غیر_تعریف_شدہ HAVE_EVP_CIPHER_CTX_سیٹ_IV
صحیح
EVP_CIPHER_CTX_سیٹ_iv(EVP_CIPHER_CTX *ctx, ثابت غیرعلامتی حرف *iv, سائز_t len)
{
	اگر (ctx == تہی)
		واپس 0;
	اگر (EVP_CIPHER_CTX_iv_لمبائی(ctx) < 0)
		واپس 0;
	اگر (len != (سائز_t)EVP_CIPHER_CTX_iv_لمبائی(ctx))
		واپس 0;
	اگر (len > EVP_MAX_IV_لمبائی)
		واپس 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	اگر (len != 0) {
		اگر (iv == تہی)
			واپس 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		حافظہ_نقل(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# ورنہ
		حافظہ_نقل(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	واپس 1;
}
#اگر_ختم /* HAVE_EVP_CIPHER_CTX_SET_IV */

#اگر_ختم /* WITH_OPENSSL */
