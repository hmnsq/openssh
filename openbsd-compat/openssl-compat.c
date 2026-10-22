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

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_DONT_OVERLOAD_OPENSSL_FUNCS
#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_OPENSSL_ENGINE
# include <openssl/engine.h>
# include <openssl/conf.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "log.h"

#ಅನ್ತರ್ಭಾವ "openssl-compat.h"

/*
 * OpenSSL version numbers: MNNFFPPS: major minor fix patch status.
 * See the OpenSSL_version_num(3ssl) man page.
 * Versions >=3 require only major versions to match.
 * For versions <3, we accept compatible fix versions (so we allow 1.0.1
 * to work with 1.0.0). Going backwards is only allowed within a patch series.
 * See https://www.openssl.org/policies/releasestrat.html
 */

ಪೂರ್ಣಾಂಕ
ssh_compatible_openssl(ದೀರ್ಘ headerver, ದೀರ್ಘ libver)
{
	ದೀರ್ಘ ಮುಖವಾಡ, hfix, lfix;

	/* exact match is always OK */
	ಆದರೆ (headerver == libver)
		ಹಿಂತಿರುಗಿ 1;

	/*
	 * For versions >= 3.0, only the major must match.
	 */
	ಆದರೆ (headerver >= 0x30000000) {
		ಮುಖವಾಡ = 0xf0000000L; /* major only */
		ಹಿಂತಿರುಗಿ (headerver & ಮುಖವಾಡ) == (libver & ಮುಖವಾಡ);
	}

	/*
	 * For versions >= 1.0.0, but <3, major,minor,status must match and
	 * library fix version must be equal to or newer than the header.
	 */
	ಮುಖವಾಡ = 0xfff0000fL; /* major,minor,status */
	hfix = (headerver & 0x000ff000) >> 12;
	lfix = (libver & 0x000ff000) >> 12;
	ಆದರೆ ( (headerver & ಮುಖವಾಡ) == (libver & ಮುಖವಾಡ) && lfix >= hfix)
		ಹಿಂತಿರುಗಿ 1;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_libcrypto_init(ಶೂನ್ಯ)
{
	uint64_t opts = OPENSSL_INIT_ಕೂಡಿಸು_ALL_CIPHERS |
	    OPENSSL_INIT_ಕೂಡಿಸು_ALL_DIGESTS;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ	USE_OPENSSL_ENGINE
	/* Enable use of crypto hardware */
	ENGINE_ತುಂಬು_builtin_engines();
	ENGINE_ರಿಜಿಸ್ಟರ್_all_complete();

	/* Tell libcrypto config file to pick up engines defined there */
	opts |= OPENSSL_INIT_ತುಂಬು_CONFIG;
#ಆದರೆ_ಅಂತ್ಯ /* USE_OPENSSL_ENGINE */

	ಹಿಂತಿರುಗಿ OPENSSL_init_crypto(opts, ಖಾಲಿ);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_EVP_DIGESTSIGN
ಪೂರ್ಣಾಂಕ
EVP_DigestSign(EVP_MD_CTX *ctx, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sigret, ಗಾತ್ರ_t *siglen,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *tbs, ಗಾತ್ರ_t tbslen)
{
	ಆದರೆ (sigret != ಖಾಲಿ) {
		ಆದರೆ (EVP_DigestSignUpdate(ctx, tbs, tbslen) <= 0)
			ಹಿಂತಿರುಗಿ 0;
	}

	ಹಿಂತಿರುಗಿ EVP_DigestSignFinal(ctx, sigret, siglen);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_EVP_DIGESTVERIFY
ಪೂರ್ಣಾಂಕ
EVP_DigestVerify(EVP_MD_CTX *ctx, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sigret, ಗಾತ್ರ_t siglen,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *tbs, ಗಾತ್ರ_t tbslen)
{
	ಆದರೆ (EVP_DigestVerifyUpdate(ctx, tbs, tbslen) <= 0)
		ಹಿಂತಿರುಗಿ -1;

	ಹಿಂತಿರುಗಿ EVP_DigestVerifyFinal(ctx, sigret, siglen);
}
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
