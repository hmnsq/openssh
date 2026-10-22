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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "log.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/err.h>

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ssherr_libcrypto(ಶೂನ್ಯ)
{
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ e;
	ಸ್ಥಿರ ಅಕ್ಷರ buf[512];
	ಅಕ್ಷರ ಸಂದೇಶ[4096];
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason = ಖಾಲಿ, *file, *ದತ್ತಾಂಶ;
	ಪೂರ್ಣಾಂಕ ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_ತುಂಬು_CRYPTO_ಅಕ್ಷರಸರಣಿಗಳು, ಖಾಲಿ);
	ಆಗ ((e = ERR_get_error_ಸಾಲು_ದತ್ತಾಂಶ(&file, &ln, &ದತ್ತಾಂಶ, &fl)) != 0) {
		ERR_error_string_n(e, buf, ಗಾತ್ರ(buf));
		snprintf(ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? ದತ್ತಾಂಶ : "");
		debug("libcrypto: '%s'", ಸಂದೇಶ);
		ಆದರೆ ((reason = ERR_reason_error_string(e)) != ಖಾಲಿ)
			snprintf(buf, ಗಾತ್ರ(buf), "error in libcrypto: %s",
			    reason);
	}
	ಆದರೆ (reason == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ buf;
}
#ಇಲ್ಲದಿದ್ದರೆ
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ssherr_libcrypto(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}
#ಆದರೆ_ಅಂತ್ಯ
