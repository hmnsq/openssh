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
पूर्णाङ्क
EVP_CIPHER_CTX_get_iv(ध्रुव EVP_CIPHER_CTX *ctx, अचिन्हित वर्ण *iv, माप_प्रकार len)
{
	यदि (ctx == रिक्त)
		प्रत्यागम 0;
	यदि (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		प्रत्यागम 0;
	यदि (len != (माप_प्रकार)EVP_CIPHER_CTX_iv_length(ctx))
		प्रत्यागम 0;
	यदि (len > EVP_MAX_IV_LENGTH)
		प्रत्यागम 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	यदि (len != 0) {
		यदि (iv == रिक्त)
			प्रत्यागम 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		स_नकल(iv, EVP_CIPHER_CTX_iv(ctx), len);
# अन्यथा
		स_नकल(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	प्रत्यागम 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
पूर्णाङ्क
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, ध्रुव अचिन्हित वर्ण *iv, माप_प्रकार len)
{
	यदि (ctx == रिक्त)
		प्रत्यागम 0;
	यदि (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		प्रत्यागम 0;
	यदि (len != (माप_प्रकार)EVP_CIPHER_CTX_iv_length(ctx))
		प्रत्यागम 0;
	यदि (len > EVP_MAX_IV_LENGTH)
		प्रत्यागम 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	यदि (len != 0) {
		यदि (iv == रिक्त)
			प्रत्यागम 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		स_नकल(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# अन्यथा
		स_नकल(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	प्रत्यागम 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
