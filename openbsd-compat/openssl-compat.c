/*
 * Copyright (c) 2005 Darren Tucker <dtucker@zip.com.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define SSH_DONT_OVERLOAD_OPENSSL_FUNCS
#അന്തര്ഭാവ "includes.h"

#ifdef WITH_OPENSSL

#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>

#ifdef USE_OPENSSL_ENGINE
# include <openssl/engine.h>
# include <openssl/conf.h>
#endif

#അന്തര്ഭാവ "log.h"

#അന്തര്ഭാവ "openssl-compat.h"

/*
 * OpenSSL version numbers: MNNFFPPS: major minor fix patch status.
 * See the OpenSSL_version_num(3ssl) man page.
 * Versions >=3 require only major versions to match.
 * For versions <3, we accept compatible fix versions (so we allow 1.0.1
 * to work with 1.0.0). Going backwards is only allowed within a patch series.
 * See https://www.openssl.org/policies/releasestrat.html
 */

പൂർണ്ണസംഖ്യ
ssh_compatible_openssl(long headerver, long libver)
{
	long mask, hfix, lfix;

	/* exact match is always OK */
	എങ്കിൽ (headerver == libver)
		തിരികെ 1;

	/*
	 * For versions >= 3.0, only the major must match.
	 */
	എങ്കിൽ (headerver >= 0x30000000) {
		mask = 0xf0000000L; /* major only */
		തിരികെ (headerver & mask) == (libver & mask);
	}

	/*
	 * For versions >= 1.0.0, but <3, major,minor,status must match and
	 * library fix version must be equal to or newer than the header.
	 */
	mask = 0xfff0000fL; /* major,minor,status */
	hfix = (headerver & 0x000ff000) >> 12;
	lfix = (libver & 0x000ff000) >> 12;
	എങ്കിൽ ( (headerver & mask) == (libver & mask) && lfix >= hfix)
		തിരികെ 1;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_libcrypto_init(ശൂന്യം)
{
	uint64_t opts = OPENSSL_INIT_ADD_ALL_CIPHERS |
	    OPENSSL_INIT_ADD_ALL_DIGESTS;

#ifdef	USE_OPENSSL_ENGINE
	/* Enable use of crypto hardware */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	/* Tell libcrypto config file to pick up engines defined there */
	opts |= OPENSSL_INIT_LOAD_CONFIG;
#endif /* USE_OPENSSL_ENGINE */

	തിരികെ OPENSSL_init_crypto(opts, ശൂന്യ);
}

#ifndef HAVE_EVP_DIGESTSIGN
പൂർണ്ണസംഖ്യ
EVP_DigestSign(EVP_MD_CTX *ctx, unsigned അക്ഷരം *sigret, size_t *siglen,
    സ്ഥിരം unsigned അക്ഷരം *tbs, size_t tbslen)
{
	എങ്കിൽ (sigret != ശൂന്യ) {
		എങ്കിൽ (EVP_DigestSignUpdate(ctx, tbs, tbslen) <= 0)
			തിരികെ 0;
	}

	തിരികെ EVP_DigestSignFinal(ctx, sigret, siglen);
}
#endif

#ifndef HAVE_EVP_DIGESTVERIFY
പൂർണ്ണസംഖ്യ
EVP_DigestVerify(EVP_MD_CTX *ctx, സ്ഥിരം unsigned അക്ഷരം *sigret, size_t siglen,
    സ്ഥിരം unsigned അക്ഷരം *tbs, size_t tbslen)
{
	എങ്കിൽ (EVP_DigestVerifyUpdate(ctx, tbs, tbslen) <= 0)
		തിരികെ -1;

	തിരികെ EVP_DigestVerifyFinal(ctx, sigret, siglen);
}
#endif

#endif /* WITH_OPENSSL */
