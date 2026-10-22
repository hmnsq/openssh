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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే WITH_OPENSSL

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ <openssl/evp.h>

#నిర్వచితం_కాకపోతే HAVE_EVP_CIPHER_CTX_GET_IV
పూర్ణాంకం
EVP_CIPHER_CTX_get_iv(స్థిరరాశి EVP_CIPHER_CTX *ctx, గుర్తులేని అక్షరం *iv, కొలత_t len)
{
	ఒకవేళ (ctx == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (EVP_CIPHER_CTX_iv_నిడివి(ctx) < 0)
		తిరిగి 0;
	ఒకవేళ (len != (కొలత_t)EVP_CIPHER_CTX_iv_నిడివి(ctx))
		తిరిగి 0;
	ఒకవేళ (len > EVP_MAX_IV_నిడివి)
		తిరిగి 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ఒకవేళ (len != 0) {
		ఒకవేళ (iv == ఖాళీ)
			తిరిగి 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		జ్ఞాపకం_నకలు(iv, EVP_CIPHER_CTX_iv(ctx), len);
# లేకపోతే
		జ్ఞాపకం_నకలు(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	తిరిగి 1;
}
#అయితే_ముగింపు /* HAVE_EVP_CIPHER_CTX_GET_IV */

#నిర్వచితం_కాకపోతే HAVE_EVP_CIPHER_CTX_సమితి_IV
పూర్ణాంకం
EVP_CIPHER_CTX_సమితి_iv(EVP_CIPHER_CTX *ctx, స్థిరరాశి గుర్తులేని అక్షరం *iv, కొలత_t len)
{
	ఒకవేళ (ctx == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (EVP_CIPHER_CTX_iv_నిడివి(ctx) < 0)
		తిరిగి 0;
	ఒకవేళ (len != (కొలత_t)EVP_CIPHER_CTX_iv_నిడివి(ctx))
		తిరిగి 0;
	ఒకవేళ (len > EVP_MAX_IV_నిడివి)
		తిరిగి 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	ఒకవేళ (len != 0) {
		ఒకవేళ (iv == ఖాళీ)
			తిరిగి 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		జ్ఞాపకం_నకలు(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# లేకపోతే
		జ్ఞాపకం_నకలు(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	తిరిగి 1;
}
#అయితే_ముగింపు /* HAVE_EVP_CIPHER_CTX_SET_IV */

#అయితే_ముగింపు /* WITH_OPENSSL */
