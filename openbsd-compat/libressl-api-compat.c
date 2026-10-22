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

#அந்தர்பாவ "includes.h"

#ifdef WITH_OPENSSL

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ <openssl/evp.h>

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
முழு
EVP_CIPHER_CTX_get_iv(மாறிலி EVP_CIPHER_CTX *ctx, unsigned எழுத்து *iv, size_t len)
{
	எனில் (ctx == வெற்று)
		திரும்பு 0;
	எனில் (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		திரும்பு 0;
	எனில் (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		திரும்பு 0;
	எனில் (len > EVP_MAX_IV_LENGTH)
		திரும்பு 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	எனில் (len != 0) {
		எனில் (iv == வெற்று)
			திரும்பு 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		memcpy(iv, EVP_CIPHER_CTX_iv(ctx), len);
# இல்லையெனில்
		memcpy(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	திரும்பு 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
முழு
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, மாறிலி unsigned எழுத்து *iv, size_t len)
{
	எனில் (ctx == வெற்று)
		திரும்பு 0;
	எனில் (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		திரும்பு 0;
	எனில் (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		திரும்பு 0;
	எனில் (len > EVP_MAX_IV_LENGTH)
		திரும்பு 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	எனில் (len != 0) {
		எனில் (iv == வெற்று)
			திரும்பு 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# இல்லையெனில்
		memcpy(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	திரும்பு 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
