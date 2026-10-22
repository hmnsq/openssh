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

#अन्तर्भाव "includes.h"

#ifdef WITH_OPENSSL

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव <openssl/evp.h>

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
पूर्णांक
EVP_CIPHER_CTX_get_iv(स्थिरांक EVP_CIPHER_CTX *ctx, अचिन्हित अक्षर *iv, माप_प्रकार len)
{
	जर (ctx == रिक्त)
		परत 0;
	जर (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		परत 0;
	जर (len != (माप_प्रकार)EVP_CIPHER_CTX_iv_length(ctx))
		परत 0;
	जर (len > EVP_MAX_IV_LENGTH)
		परत 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	जर (len != 0) {
		जर (iv == रिक्त)
			परत 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		स_नकल(iv, EVP_CIPHER_CTX_iv(ctx), len);
# अन्यथा
		स_नकल(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	परत 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
पूर्णांक
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, स्थिरांक अचिन्हित अक्षर *iv, माप_प्रकार len)
{
	जर (ctx == रिक्त)
		परत 0;
	जर (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		परत 0;
	जर (len != (माप_प्रकार)EVP_CIPHER_CTX_iv_length(ctx))
		परत 0;
	जर (len > EVP_MAX_IV_LENGTH)
		परत 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	जर (len != 0) {
		जर (iv == रिक्त)
			परत 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		स_नकल(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# अन्यथा
		स_नकल(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	परत 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
