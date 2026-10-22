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

#ضمن "includes.h"

#ifdef WITH_OPENSSL

#ضمن <sys/types.h>

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <openssl/evp.h>

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
صحيح
EVP_CIPHER_CTX_get_iv(ثابت EVP_CIPHER_CTX *ctx, unsigned حرف *iv, size_t len)
{
	ܐܢ (ctx == عدم)
		ܦܢܐ 0;
	ܐܢ (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		ܦܢܐ 0;
	ܐܢ (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		ܦܢܐ 0;
	ܐܢ (len > EVP_MAX_IV_LENGTH)
		ܦܢܐ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ܐܢ (len != 0) {
		ܐܢ (iv == عدم)
			ܦܢܐ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		memcpy(iv, EVP_CIPHER_CTX_iv(ctx), len);
# ܐܚܪܢܐ
		memcpy(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	ܦܢܐ 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
صحيح
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, ثابت unsigned حرف *iv, size_t len)
{
	ܐܢ (ctx == عدم)
		ܦܢܐ 0;
	ܐܢ (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		ܦܢܐ 0;
	ܐܢ (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		ܦܢܐ 0;
	ܐܢ (len > EVP_MAX_IV_LENGTH)
		ܦܢܐ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ܐܢ (len != 0) {
		ܐܢ (iv == عدم)
			ܦܢܐ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# ܐܚܪܢܐ
		memcpy(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	ܦܢܐ 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
