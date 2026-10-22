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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <errno.h>
#समावेश <string.h>

#समावेश "log.h"

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/err.h>

स्थिर अक्षर *
ssherr_libcrypto(व्योम)
{
	अचिन्हित दीर्घ e;
	अटल अक्षर buf[512];
	अक्षर संदेश[4096];
	स्थिर अक्षर *reason = शून्य, *file, *तथ्य;
	पूर्णांक ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, शून्य);
	जबतक ((e = ERR_get_error_पंक्ति_तथ्य(&file, &ln, &तथ्य, &fl)) != 0) {
		ERR_error_string_n(e, buf, माप(buf));
		snprintf(संदेश, माप(संदेश), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? तथ्य : "");
		debug("libcrypto: '%s'", संदेश);
		अगर ((reason = ERR_reason_error_string(e)) != शून्य)
			snprintf(buf, माप(buf), "error in libcrypto: %s",
			    reason);
	}
	अगर (reason == शून्य)
		वापस शून्य;
	वापस buf;
}
#अन्यथा
स्थिर अक्षर *
ssherr_libcrypto(व्योम)
{
	वापस शून्य;
}
#पूर्ण_अगर
