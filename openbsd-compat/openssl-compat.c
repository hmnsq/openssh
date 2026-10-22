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

#تعریف_کړه SSH_DONT_OVERLOAD_OPENSSL_FUNCS
#ضمن "includes.h"

#که_تعریف_شوی WITH_OPENSSL

#ضمن <stdarg.h>
#ضمن <string.h>

#که_تعریف_شوی USE_OPENSSL_ENGINE
# include <openssl/engine.h>
# include <openssl/conf.h>
#د_که_پای

#ضمن "log.h"

#ضمن "openssl-compat.h"

/*
 * OpenSSL version numbers: MNNFFPPS: major minor fix patch status.
 * See the OpenSSL_version_num(3ssl) man page.
 * Versions >=3 require only major versions to match.
 * For versions <3, we accept compatible fix versions (so we allow 1.0.1
 * to work with 1.0.0). Going backwards is only allowed within a patch series.
 * See https://www.openssl.org/policies/releasestrat.html
 */

صحيح
ssh_compatible_openssl(اوږد headerver, اوږد libver)
{
	اوږد ماسک, hfix, lfix;

	/* exact match is always OK */
	إذا (headerver == libver)
		أرجع 1;

	/*
	 * For versions >= 3.0, only the major must match.
	 */
	إذا (headerver >= 0x30000000) {
		ماسک = 0xf0000000L; /* major only */
		أرجع (headerver & ماسک) == (libver & ماسک);
	}

	/*
	 * For versions >= 1.0.0, but <3, major,minor,status must match and
	 * library fix version must be equal to or newer than the header.
	 */
	ماسک = 0xfff0000fL; /* major,minor,status */
	hfix = (headerver & 0x000ff000) >> 12;
	lfix = (libver & 0x000ff000) >> 12;
	إذا ( (headerver & ماسک) == (libver & ماسک) && lfix >= hfix)
		أرجع 1;
	أرجع 0;
}

صحيح
ssh_libcrypto_init(فراغ)
{
	uint64_t opts = OPENSSL_INIT_جمع_کړه_ALL_CIPHERS |
	    OPENSSL_INIT_جمع_کړه_ALL_DIGESTS;

#که_تعریف_شوی	USE_OPENSSL_ENGINE
	/* Enable use of crypto hardware */
	ENGINE_بارول_builtin_engines();
	ENGINE_ثبتوونکی_all_complete();

	/* Tell libcrypto config file to pick up engines defined there */
	opts |= OPENSSL_INIT_بارول_CONFIG;
#د_که_پای /* USE_OPENSSL_ENGINE */

	أرجع OPENSSL_init_crypto(opts, عدم);
}

#که_نه_تعریف_شوی HAVE_EVP_DIGESTSIGN
صحيح
EVP_DigestSign(EVP_MD_CTX *ctx, بینښه حرف *sigret, اندازه_t *siglen,
    ثابت بینښه حرف *tbs, اندازه_t tbslen)
{
	إذا (sigret != عدم) {
		إذا (EVP_DigestSignUpdate(ctx, tbs, tbslen) <= 0)
			أرجع 0;
	}

	أرجع EVP_DigestSignFinal(ctx, sigret, siglen);
}
#د_که_پای

#که_نه_تعریف_شوی HAVE_EVP_DIGESTVERIFY
صحيح
EVP_DigestVerify(EVP_MD_CTX *ctx, ثابت بینښه حرف *sigret, اندازه_t siglen,
    ثابت بینښه حرف *tbs, اندازه_t tbslen)
{
	إذا (EVP_DigestVerifyUpdate(ctx, tbs, tbslen) <= 0)
		أرجع -1;

	أرجع EVP_DigestVerifyFinal(ctx, sigret, siglen);
}
#د_که_پای

#د_که_پای /* WITH_OPENSSL */
