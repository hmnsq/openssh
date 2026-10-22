/* $OpenBSD: ssherr-libcrypto.c,v 1.2 2026/06/30 03:42:53 tb Exp $ */
/*
 * Copyright (c) 2026 Darren Tucker
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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/err.h>

ਅਚਲ ਅੱਖਰ *
ssherr_libcrypto(ਖਾਲੀ)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ e;
	ਸਥਿਰ ਅੱਖਰ buf[512];
	ਅੱਖਰ ਸੁਨੇਹਾ[4096];
	ਅਚਲ ਅੱਖਰ *reason = ਨਿਰਾ, *file, *ਅੰਕੜੇ;
	ਪੂਰਨ ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_ਲੱਦੋ_CRYPTO_ਲੜੀਆਂ, ਨਿਰਾ);
	ਜਦੋਂ ((e = ERR_get_error_ਸਤਰ_ਅੰਕੜੇ(&file, &ln, &ਅੰਕੜੇ, &fl)) != 0) {
		ERR_error_string_n(e, buf, ਆਕਾਰ(buf));
		snprintf(ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? ਅੰਕੜੇ : "");
		debug("libcrypto: '%s'", ਸੁਨੇਹਾ);
		ਜੇ ((reason = ERR_reason_error_string(e)) != ਨਿਰਾ)
			snprintf(buf, ਆਕਾਰ(buf), "error in libcrypto: %s",
			    reason);
	}
	ਜੇ (reason == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਵਾਪਸ buf;
}
#ਨਹੀਂਤਾਂ
ਅਚਲ ਅੱਖਰ *
ssherr_libcrypto(ਖਾਲੀ)
{
	ਵਾਪਸ ਨਿਰਾ;
}
#ਜੇ_ਅੰਤ
