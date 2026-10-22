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

#تعریف_کرو SSH_DONT_OVERLOAD_OPENSSL_FUNCS
#شامل "includes.h"

#اگر_تعریف_شدہ WITH_OPENSSL

#شامل <stdarg.h>
#شامل <string.h>

#اگر_تعریف_شدہ USE_OPENSSL_ENGINE
# include <openssl/engine.h>
# include <openssl/conf.h>
#اگر_ختم

#شامل "log.h"

#شامل "openssl-compat.h"

/*
 * OpenSSL version numbers: MNNFFPPS: major minor fix patch status.
 * See the OpenSSL_version_num(3ssl) man page.
 * Versions >=3 require only major versions to match.
 * For versions <3, we accept compatible fix versions (so we allow 1.0.1
 * to work with 1.0.0). Going backwards is only allowed within a patch series.
 * See https://www.openssl.org/policies/releasestrat.html
 */

صحیح
ssh_compatible_openssl(طویل headerver, طویل libver)
{
	طویل نقاب, hfix, lfix;

	/* exact match is always OK */
	اگر (headerver == libver)
		واپس 1;

	/*
	 * For versions >= 3.0, only the major must match.
	 */
	اگر (headerver >= 0x30000000) {
		نقاب = 0xf0000000L; /* major only */
		واپس (headerver & نقاب) == (libver & نقاب);
	}

	/*
	 * For versions >= 1.0.0, but <3, major,minor,status must match and
	 * library fix version must be equal to or newer than the header.
	 */
	نقاب = 0xfff0000fL; /* major,minor,status */
	hfix = (headerver & 0x000ff000) >> 12;
	lfix = (libver & 0x000ff000) >> 12;
	اگر ( (headerver & نقاب) == (libver & نقاب) && lfix >= hfix)
		واپس 1;
	واپس 0;
}

صحیح
ssh_libcrypto_init(خالی)
{
	uint64_t opts = OPENSSL_INIT_جوڑو_ALL_CIPHERS |
	    OPENSSL_INIT_جوڑو_ALL_DIGESTS;

#اگر_تعریف_شدہ	USE_OPENSSL_ENGINE
	/* Enable use of crypto hardware */
	ENGINE_بھرو_builtin_engines();
	ENGINE_رجسٹر_all_complete();

	/* Tell libcrypto config file to pick up engines defined there */
	opts |= OPENSSL_INIT_بھرو_CONFIG;
#اگر_ختم /* USE_OPENSSL_ENGINE */

	واپس OPENSSL_init_crypto(opts, تہی);
}

#اگر_غیر_تعریف_شدہ HAVE_EVP_DIGESTSIGN
صحیح
EVP_DigestSign(EVP_MD_CTX *ctx, غیرعلامتی حرف *sigret, سائز_t *siglen,
    ثابت غیرعلامتی حرف *tbs, سائز_t tbslen)
{
	اگر (sigret != تہی) {
		اگر (EVP_DigestSignUpdate(ctx, tbs, tbslen) <= 0)
			واپس 0;
	}

	واپس EVP_DigestSignFinal(ctx, sigret, siglen);
}
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_EVP_DIGESTVERIFY
صحیح
EVP_DigestVerify(EVP_MD_CTX *ctx, ثابت غیرعلامتی حرف *sigret, سائز_t siglen,
    ثابت غیرعلامتی حرف *tbs, سائز_t tbslen)
{
	اگر (EVP_DigestVerifyUpdate(ctx, tbs, tbslen) <= 0)
		واپس -1;

	واپس EVP_DigestVerifyFinal(ctx, sigret, siglen);
}
#اگر_ختم

#اگر_ختم /* WITH_OPENSSL */
