/*
 * Copyright (c) 2005 Darren Tucker
 * Copyright (c) 2005 Damien Miller
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

#ವ್ಯಾಖ್ಯಾನಿಸು BUFSZ 2048

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ failed = 0;

ಸ್ಥಿರ ಶೂನ್ಯ
fail(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

ಪೂರ್ಣಾಂಕ x_snprintf(ಅಕ್ಷರ *str, ಗಾತ್ರ_t ಎಣಿಕೆ_2, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	ಗಾತ್ರ_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, ಎಣಿಕೆ_2, fmt, ap);
	va_end(ap);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ b[5];
	ಅಕ್ಷರ *src = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret;

	memset(b, 'X', ಗಾತ್ರ(b));
	ret = snprintf(b, 5, "123456789");
	ಆದರೆ (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	ಆದರೆ ((src = ಸ್ಮರಣೆ_ಕೊಡು(BUFSZ)) == ಖಾಲಿ) {
		fail("malloc failed");
	} ಇಲ್ಲದಿದ್ದರೆ {
		memset(src, 'a', BUFSZ);
		snprintf(b, ಗಾತ್ರ(b), "%.*s", 1, src);
		ಆದರೆ (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	ಆದರೆ (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	ಆದರೆ (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	ಬಿಡುಗಡೆ(src);
	ಹಿಂತಿರುಗಿ failed;
}
