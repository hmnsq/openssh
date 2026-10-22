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

#నిర్వచించు SSH_DONT_OVERLOAD_OPENSSL_FUNCS
#అన్తర్భావ "includes.h"

#నిర్వచితమైతే WITH_OPENSSL

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>

#నిర్వచితమైతే USE_OPENSSL_ENGINE
# include <openssl/engine.h>
# include <openssl/conf.h>
#అయితే_ముగింపు

#అన్తర్భావ "log.h"

#అన్తర్భావ "openssl-compat.h"

/*
 * OpenSSL version numbers: MNNFFPPS: major minor fix patch status.
 * See the OpenSSL_version_num(3ssl) man page.
 * Versions >=3 require only major versions to match.
 * For versions <3, we accept compatible fix versions (so we allow 1.0.1
 * to work with 1.0.0). Going backwards is only allowed within a patch series.
 * See https://www.openssl.org/policies/releasestrat.html
 */

పూర్ణాంకం
ssh_compatible_openssl(దీర్ఘ headerver, దీర్ఘ libver)
{
	దీర్ఘ ముసుగు, hfix, lfix;

	/* exact match is always OK */
	ఒకవేళ (headerver == libver)
		తిరిగి 1;

	/*
	 * For versions >= 3.0, only the major must match.
	 */
	ఒకవేళ (headerver >= 0x30000000) {
		ముసుగు = 0xf0000000L; /* major only */
		తిరిగి (headerver & ముసుగు) == (libver & ముసుగు);
	}

	/*
	 * For versions >= 1.0.0, but <3, major,minor,status must match and
	 * library fix version must be equal to or newer than the header.
	 */
	ముసుగు = 0xfff0000fL; /* major,minor,status */
	hfix = (headerver & 0x000ff000) >> 12;
	lfix = (libver & 0x000ff000) >> 12;
	ఒకవేళ ( (headerver & ముసుగు) == (libver & ముసుగు) && lfix >= hfix)
		తిరిగి 1;
	తిరిగి 0;
}

పూర్ణాంకం
ssh_libcrypto_init(శూన్య)
{
	uint64_t opts = OPENSSL_INIT_కూడు_ALL_CIPHERS |
	    OPENSSL_INIT_కూడు_ALL_DIGESTS;

#నిర్వచితమైతే	USE_OPENSSL_ENGINE
	/* Enable use of crypto hardware */
	ENGINE_ఎక్కించు_builtin_engines();
	ENGINE_రిజిస్టరు_all_complete();

	/* Tell libcrypto config file to pick up engines defined there */
	opts |= OPENSSL_INIT_ఎక్కించు_CONFIG;
#అయితే_ముగింపు /* USE_OPENSSL_ENGINE */

	తిరిగి OPENSSL_init_crypto(opts, ఖాళీ);
}

#నిర్వచితం_కాకపోతే HAVE_EVP_DIGESTSIGN
పూర్ణాంకం
EVP_DigestSign(EVP_MD_CTX *ctx, గుర్తులేని అక్షరం *sigret, కొలత_t *siglen,
    స్థిరరాశి గుర్తులేని అక్షరం *tbs, కొలత_t tbslen)
{
	ఒకవేళ (sigret != ఖాళీ) {
		ఒకవేళ (EVP_DigestSignUpdate(ctx, tbs, tbslen) <= 0)
			తిరిగి 0;
	}

	తిరిగి EVP_DigestSignFinal(ctx, sigret, siglen);
}
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_EVP_DIGESTVERIFY
పూర్ణాంకం
EVP_DigestVerify(EVP_MD_CTX *ctx, స్థిరరాశి గుర్తులేని అక్షరం *sigret, కొలత_t siglen,
    స్థిరరాశి గుర్తులేని అక్షరం *tbs, కొలత_t tbslen)
{
	ఒకవేళ (EVP_DigestVerifyUpdate(ctx, tbs, tbslen) <= 0)
		తిరిగి -1;

	తిరిగి EVP_DigestVerifyFinal(ctx, sigret, siglen);
}
#అయితే_ముగింపు

#అయితే_ముగింపు /* WITH_OPENSSL */
