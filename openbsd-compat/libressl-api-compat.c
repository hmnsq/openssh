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

#که_تعریف_شوی WITH_OPENSSL

#ضمن <sys/types.h>

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <openssl/evp.h>

#که_نه_تعریف_شوی HAVE_EVP_CIPHER_CTX_GET_IV
صحيح
EVP_CIPHER_CTX_get_iv(ثابت EVP_CIPHER_CTX *ctx, بینښه حرف *iv, اندازه_t len)
{
	إذا (ctx == عدم)
		أرجع 0;
	إذا (EVP_CIPHER_CTX_iv_اوږدتیا(ctx) < 0)
		أرجع 0;
	إذا (len != (اندازه_t)EVP_CIPHER_CTX_iv_اوږدتیا(ctx))
		أرجع 0;
	إذا (len > EVP_MAX_IV_اوږدتیا)
		أرجع 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	إذا (len != 0) {
		إذا (iv == عدم)
			أرجع 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		حافظه_نقل(iv, EVP_CIPHER_CTX_iv(ctx), len);
# وإلا
		حافظه_نقل(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	أرجع 1;
}
#د_که_پای /* HAVE_EVP_CIPHER_CTX_GET_IV */

#که_نه_تعریف_شوی HAVE_EVP_CIPHER_CTX_سېټ_IV
صحيح
EVP_CIPHER_CTX_سېټ_iv(EVP_CIPHER_CTX *ctx, ثابت بینښه حرف *iv, اندازه_t len)
{
	إذا (ctx == عدم)
		أرجع 0;
	إذا (EVP_CIPHER_CTX_iv_اوږدتیا(ctx) < 0)
		أرجع 0;
	إذا (len != (اندازه_t)EVP_CIPHER_CTX_iv_اوږدتیا(ctx))
		أرجع 0;
	إذا (len > EVP_MAX_IV_اوږدتیا)
		أرجع 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	إذا (len != 0) {
		إذا (iv == عدم)
			أرجع 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		حافظه_نقل(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# وإلا
		حافظه_نقل(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	أرجع 1;
}
#د_که_پای /* HAVE_EVP_CIPHER_CTX_SET_IV */

#د_که_پای /* WITH_OPENSSL */
