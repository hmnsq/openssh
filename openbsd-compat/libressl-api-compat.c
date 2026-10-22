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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_CIPHER_CTX_GET_IV
ਪੂਰਨ
EVP_CIPHER_CTX_get_iv(ਅਚਲ EVP_CIPHER_CTX *ctx, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *iv, ਮਾਪ_t len)
{
	ਜੇ (ctx == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (EVP_CIPHER_CTX_iv_ਲੰਮਾਈ(ctx) < 0)
		ਵਾਪਸ 0;
	ਜੇ (len != (ਮਾਪ_t)EVP_CIPHER_CTX_iv_ਲੰਮਾਈ(ctx))
		ਵਾਪਸ 0;
	ਜੇ (len > EVP_MAX_IV_ਲੰਮਾਈ)
		ਵਾਪਸ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ਜੇ (len != 0) {
		ਜੇ (iv == ਨਿਰਾ)
			ਵਾਪਸ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(iv, EVP_CIPHER_CTX_iv(ctx), len);
# ਨਹੀਂਤਾਂ
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	ਵਾਪਸ 1;
}
#ਜੇ_ਅੰਤ /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_CIPHER_CTX_ਸੈੱਟ_IV
ਪੂਰਨ
EVP_CIPHER_CTX_ਸੈੱਟ_iv(EVP_CIPHER_CTX *ctx, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *iv, ਮਾਪ_t len)
{
	ਜੇ (ctx == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (EVP_CIPHER_CTX_iv_ਲੰਮਾਈ(ctx) < 0)
		ਵਾਪਸ 0;
	ਜੇ (len != (ਮਾਪ_t)EVP_CIPHER_CTX_iv_ਲੰਮਾਈ(ctx))
		ਵਾਪਸ 0;
	ਜੇ (len > EVP_MAX_IV_ਲੰਮਾਈ)
		ਵਾਪਸ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ਜੇ (len != 0) {
		ਜੇ (iv == ਨਿਰਾ)
			ਵਾਪਸ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# ਨਹੀਂਤਾਂ
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	ਵਾਪਸ 1;
}
#ਜੇ_ਅੰਤ /* HAVE_EVP_CIPHER_CTX_SET_IV */

#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
