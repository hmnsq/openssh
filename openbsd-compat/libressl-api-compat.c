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

#समावेश "includes.h"

#अगर_घोषित WITH_OPENSSL

#समावेश <sys/types.h>

#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश <openssl/evp.h>

#अगर_अघोषित HAVE_EVP_CIPHER_CTX_GET_IV
पूर्णांक
EVP_CIPHER_CTX_get_iv(स्थिर EVP_CIPHER_CTX *ctx, अचिन्हित अक्षर *iv, माप_प्रकार len)
{
	अगर (ctx == शून्य)
		वापस 0;
	अगर (EVP_CIPHER_CTX_iv_लंबाई(ctx) < 0)
		वापस 0;
	अगर (len != (माप_प्रकार)EVP_CIPHER_CTX_iv_लंबाई(ctx))
		वापस 0;
	अगर (len > EVP_MAX_IV_लंबाई)
		वापस 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	अगर (len != 0) {
		अगर (iv == शून्य)
			वापस 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		स_नकल(iv, EVP_CIPHER_CTX_iv(ctx), len);
# अन्यथा
		स_नकल(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	वापस 1;
}
#पूर्ण_अगर /* HAVE_EVP_CIPHER_CTX_GET_IV */

#अगर_अघोषित HAVE_EVP_CIPHER_CTX_SET_IV
पूर्णांक
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, स्थिर अचिन्हित अक्षर *iv, माप_प्रकार len)
{
	अगर (ctx == शून्य)
		वापस 0;
	अगर (EVP_CIPHER_CTX_iv_लंबाई(ctx) < 0)
		वापस 0;
	अगर (len != (माप_प्रकार)EVP_CIPHER_CTX_iv_लंबाई(ctx))
		वापस 0;
	अगर (len > EVP_MAX_IV_लंबाई)
		वापस 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	अगर (len != 0) {
		अगर (iv == शून्य)
			वापस 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		स_नकल(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# अन्यथा
		स_नकल(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	वापस 1;
}
#पूर्ण_अगर /* HAVE_EVP_CIPHER_CTX_SET_IV */

#पूर्ण_अगर /* WITH_OPENSSL */
