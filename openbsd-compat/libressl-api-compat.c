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

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
ཧྲིལ
EVP_CIPHER_CTX_get_iv(const EVP_CIPHER_CTX *ctx, unsigned var_na *iv, size_t len)
{
	གལ་སྲིད (ctx == NULL)
		ལོག 0;
	གལ་སྲིད (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		ལོག 0;
	གལ་སྲིད (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		ལོག 0;
	གལ་སྲིད (len > EVP_MAX_IV_LENGTH)
		ལོག 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	གལ་སྲིད (len != 0) {
		གལ་སྲིད (iv == NULL)
			ལོག 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		memcpy(iv, EVP_CIPHER_CTX_iv(ctx), len);
# དེ་མིན
		memcpy(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	ལོག 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
ཧྲིལ
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, const unsigned var_na *iv, size_t len)
{
	གལ་སྲིད (ctx == NULL)
		ལོག 0;
	གལ་སྲིད (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		ལོག 0;
	གལ་སྲིད (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		ལོག 0;
	གལ་སྲིད (len > EVP_MAX_IV_LENGTH)
		ལོག 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	གལ་སྲིད (len != 0) {
		གལ་སྲིད (iv == NULL)
			ལོག 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# དེ་མིན
		memcpy(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	ལོག 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
