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

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_DONT_OVERLOAD_OPENSSL_FUNCS
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_OPENSSL_ENGINE
# include <openssl/engine.h>
# include <openssl/conf.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "openssl-compat.h"

/*
 * OpenSSL version numbers: MNNFFPPS: major minor fix patch status.
 * See the OpenSSL_version_num(3ssl) man page.
 * Versions >=3 require only major versions to match.
 * For versions <3, we accept compatible fix versions (so we allow 1.0.1
 * to work with 1.0.0). Going backwards is only allowed within a patch series.
 * See https://www.openssl.org/policies/releasestrat.html
 */

ਪੂਰਨ
ssh_compatible_openssl(ਲੰਮਾ headerver, ਲੰਮਾ libver)
{
	ਲੰਮਾ ਨਕਾਬ, hfix, lfix;

	/* exact match is always OK */
	ਜੇ (headerver == libver)
		ਵਾਪਸ 1;

	/*
	 * For versions >= 3.0, only the major must match.
	 */
	ਜੇ (headerver >= 0x30000000) {
		ਨਕਾਬ = 0xf0000000L; /* major only */
		ਵਾਪਸ (headerver & ਨਕਾਬ) == (libver & ਨਕਾਬ);
	}

	/*
	 * For versions >= 1.0.0, but <3, major,minor,status must match and
	 * library fix version must be equal to or newer than the header.
	 */
	ਨਕਾਬ = 0xfff0000fL; /* major,minor,status */
	hfix = (headerver & 0x000ff000) >> 12;
	lfix = (libver & 0x000ff000) >> 12;
	ਜੇ ( (headerver & ਨਕਾਬ) == (libver & ਨਕਾਬ) && lfix >= hfix)
		ਵਾਪਸ 1;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_libcrypto_init(ਖਾਲੀ)
{
	uint64_t opts = OPENSSL_INIT_ਜੋੜੋ_ALL_CIPHERS |
	    OPENSSL_INIT_ਜੋੜੋ_ALL_DIGESTS;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ	USE_OPENSSL_ENGINE
	/* Enable use of crypto hardware */
	ENGINE_ਲੱਦੋ_builtin_engines();
	ENGINE_ਰਜਿਸਟਰ_all_complete();

	/* Tell libcrypto config file to pick up engines defined there */
	opts |= OPENSSL_INIT_ਲੱਦੋ_CONFIG;
#ਜੇ_ਅੰਤ /* USE_OPENSSL_ENGINE */

	ਵਾਪਸ OPENSSL_init_crypto(opts, ਨਿਰਾ);
}

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_DIGESTSIGN
ਪੂਰਨ
EVP_DigestSign(EVP_MD_CTX *ctx, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sigret, ਮਾਪ_t *siglen,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *tbs, ਮਾਪ_t tbslen)
{
	ਜੇ (sigret != ਨਿਰਾ) {
		ਜੇ (EVP_DigestSignUpdate(ctx, tbs, tbslen) <= 0)
			ਵਾਪਸ 0;
	}

	ਵਾਪਸ EVP_DigestSignFinal(ctx, sigret, siglen);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_DIGESTVERIFY
ਪੂਰਨ
EVP_DigestVerify(EVP_MD_CTX *ctx, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sigret, ਮਾਪ_t siglen,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *tbs, ਮਾਪ_t tbslen)
{
	ਜੇ (EVP_DigestVerifyUpdate(ctx, tbs, tbslen) <= 0)
		ਵਾਪਸ -1;

	ਵਾਪਸ EVP_DigestVerifyFinal(ctx, sigret, siglen);
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
