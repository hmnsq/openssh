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

#অন্তর্ভাব "includes.h"

#ifdef WITH_OPENSSL

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব <openssl/evp.h>

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
পূর্ণাঙ্ক
EVP_CIPHER_CTX_get_iv(ধ্রুব EVP_CIPHER_CTX *ctx, unsigned বর্ণ *iv, size_t len)
{
	যদি (ctx == রিক্ত)
		প্রত্যাগম 0;
	যদি (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		প্রত্যাগম 0;
	যদি (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		প্রত্যাগম 0;
	যদি (len > EVP_MAX_IV_LENGTH)
		প্রত্যাগম 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	যদি (len != 0) {
		যদি (iv == রিক্ত)
			প্রত্যাগম 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		memcpy(iv, EVP_CIPHER_CTX_iv(ctx), len);
# অন্যথা
		memcpy(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	প্রত্যাগম 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
পূর্ণাঙ্ক
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, ধ্রুব unsigned বর্ণ *iv, size_t len)
{
	যদি (ctx == রিক্ত)
		প্রত্যাগম 0;
	যদি (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		প্রত্যাগম 0;
	যদি (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		প্রত্যাগম 0;
	যদি (len > EVP_MAX_IV_LENGTH)
		প্রত্যাগম 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	যদি (len != 0) {
		যদি (iv == রিক্ত)
			প্রত্যাগম 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# অন্যথা
		memcpy(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	প্রত্যাগম 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
