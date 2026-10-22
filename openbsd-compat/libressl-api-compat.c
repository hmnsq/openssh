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

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL

#ضمن <sys/types.h>

#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن <openssl/evp.h>

#جيڪڏهن_وصف_نه_ٿيل HAVE_EVP_CIPHER_CTX_GET_IV
صحيح
EVP_CIPHER_CTX_get_iv(ثابت EVP_CIPHER_CTX *ctx, بنانشان حرف *iv, سائيز_t len)
{
	إذا (ctx == عدم)
		أرجع 0;
	إذا (EVP_CIPHER_CTX_iv_ڊيگهائي(ctx) < 0)
		أرجع 0;
	إذا (len != (سائيز_t)EVP_CIPHER_CTX_iv_ڊيگهائي(ctx))
		أرجع 0;
	إذا (len > EVP_MAX_IV_ڊيگهائي)
		أرجع 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	إذا (len != 0) {
		إذا (iv == عدم)
			أرجع 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		يادگيري_نقل(iv, EVP_CIPHER_CTX_iv(ctx), len);
# وإلا
		يادگيري_نقل(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	أرجع 1;
}
#جيڪڏهن_پورو /* HAVE_EVP_CIPHER_CTX_GET_IV */

#جيڪڏهن_وصف_نه_ٿيل HAVE_EVP_CIPHER_CTX_سيٽ_IV
صحيح
EVP_CIPHER_CTX_سيٽ_iv(EVP_CIPHER_CTX *ctx, ثابت بنانشان حرف *iv, سائيز_t len)
{
	إذا (ctx == عدم)
		أرجع 0;
	إذا (EVP_CIPHER_CTX_iv_ڊيگهائي(ctx) < 0)
		أرجع 0;
	إذا (len != (سائيز_t)EVP_CIPHER_CTX_iv_ڊيگهائي(ctx))
		أرجع 0;
	إذا (len > EVP_MAX_IV_ڊيگهائي)
		أرجع 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	إذا (len != 0) {
		إذا (iv == عدم)
			أرجع 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		يادگيري_نقل(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# وإلا
		يادگيري_نقل(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	أرجع 1;
}
#جيڪڏهن_پورو /* HAVE_EVP_CIPHER_CTX_SET_IV */

#جيڪڏهن_پورو /* WITH_OPENSSL */
