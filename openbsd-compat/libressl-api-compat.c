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

#അന്തര്ഭാവ "includes.h"

#ifdef WITH_OPENSSL

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ <openssl/evp.h>

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
പൂർണ്ണസംഖ്യ
EVP_CIPHER_CTX_get_iv(സ്ഥിരം EVP_CIPHER_CTX *ctx, unsigned അക്ഷരം *iv, size_t len)
{
	എങ്കിൽ (ctx == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		തിരികെ 0;
	എങ്കിൽ (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		തിരികെ 0;
	എങ്കിൽ (len > EVP_MAX_IV_LENGTH)
		തിരികെ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	എങ്കിൽ (len != 0) {
		എങ്കിൽ (iv == ശൂന്യ)
			തിരികെ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV
		memcpy(iv, EVP_CIPHER_CTX_iv(ctx), len);
# അല്ലെങ്കിൽ
		memcpy(iv, ctx->iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV */
	}
	തിരികെ 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
പൂർണ്ണസംഖ്യ
EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx, സ്ഥിരം unsigned അക്ഷരം *iv, size_t len)
{
	എങ്കിൽ (ctx == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (EVP_CIPHER_CTX_iv_length(ctx) < 0)
		തിരികെ 0;
	എങ്കിൽ (len != (size_t)EVP_CIPHER_CTX_iv_length(ctx))
		തിരികെ 0;
	എങ്കിൽ (len > EVP_MAX_IV_LENGTH)
		തിരികെ 0; /* sanity check; shouldn't happen */
	/*
	 * Skip the memcpy entirely when the requested IV length is zero,
	 * since the iv pointer may be NULL or invalid.
	 */
	എങ്കിൽ (len != 0) {
		എങ്കിൽ (iv == ശൂന്യ)
			തിരികെ 0;
# ifdef HAVE_EVP_CIPHER_CTX_IV_NOCONST
		memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, len);
# അല്ലെങ്കിൽ
		memcpy(ctx->iv, iv, len);
# endif /* HAVE_EVP_CIPHER_CTX_IV_NOCONST */
	}
	തിരികെ 1;
}
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#endif /* WITH_OPENSSL */
