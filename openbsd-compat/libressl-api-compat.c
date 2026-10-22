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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef WITH_OPENSSL

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
EVP_CIPHER_CTX_get_iv(ଅଚଳ EVP_CIPHER_CTX *ctx, unsigned ଅକ୍ଷର *iv, size_t len)
{
	ଯଦି (ctx == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		ଫେରନ୍ତୁ 0;
	ଯଦି (len > EVP_MAX_IV_LENGTH)
		ଫେରନ୍ତୁ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ଯଦି (len != 0) {
		ଯଦି (iv == ଖାଲି)
			ଫେରନ୍ତୁ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		memcpy(iv, EVP_CIPHER_CTX_iv(ctx), len);
# ଅନ୍ୟଥା
		memcpy(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	ଫେରନ୍ତୁ 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, ଅଚଳ unsigned ଅକ୍ଷର *iv, size_t len)
{
	ଯଦି (ctx == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		ଫେରନ୍ତୁ 0;
	ଯଦି (len > EVP_MAX_IV_LENGTH)
		ଫେରନ୍ତୁ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ଯଦି (len != 0) {
		ଯଦି (iv == ଖାଲି)
			ଫେରନ୍ତୁ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# ଅନ୍ୟଥା
		memcpy(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	ଫେରନ୍ତୁ 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
