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

#ifdef WITH_OPENSSL

#شامل <sys/types.h>

#شامل <stdlib.h>
#شامل <string.h>

#شامل <openssl/evp.h>

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
صحیح
EVP_CIPHER_CTX_get_iv(ثابت EVP_CIPHER_CTX *ctx, unsigned نویسه *iv, size_t len)
{
	اگر (ctx == پوچ)
		بازگشت 0;
	اگر (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		بازگشت 0;
	اگر (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		بازگشت 0;
	اگر (len > EVP_MAX_IV_LENGTH)
		بازگشت 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	اگر (len != 0) {
		اگر (iv == پوچ)
			بازگشت 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		memcpy(iv, EVP_CIPHER_CTX_iv(ctx), len);
# وگرنه
		memcpy(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	بازگشت 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
صحیح
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, ثابت unsigned نویسه *iv, size_t len)
{
	اگر (ctx == پوچ)
		بازگشت 0;
	اگر (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		بازگشت 0;
	اگر (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		بازگشت 0;
	اگر (len > EVP_MAX_IV_LENGTH)
		بازگشت 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	اگر (len != 0) {
		اگر (iv == پوچ)
			بازگشت 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# وگرنه
		memcpy(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	بازگشت 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
