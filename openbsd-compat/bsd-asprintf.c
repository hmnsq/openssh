/*
 * Copyright (c) 2004 Darren Tucker.
 *
 * Based originally on asprintf.c from OpenBSD:
 * Copyright (c) 1997 Todd C. Miller <Todd.Miller@courtesan.com>
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

/*
 * Don't let systems with broken printf(3) avoid our replacements
 * via asprintf(3)/vasprintf(3) calling libc internally.
 */
#ಆದರೆ defined(BROKEN_SNPRINTF)
# undef HAVE_VASPRINTF
# undef HAVE_ASPRINTF
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_VASPRINTF

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ವ್ಯಾಖ್ಯಾನಿಸು INIT_SZ	128

ಪೂರ್ಣಾಂಕ
vasprintf(ಅಕ್ಷರ **str, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, va_list ap)
{
	ಪೂರ್ಣಾಂಕ ret = -1;
	va_list ap2;
	ಅಕ್ಷರ *string, *newstr;
	ಗಾತ್ರ_t len;

	VA_COPY(ap2, ap);
	ಆದರೆ ((string = ಸ್ಮರಣೆ_ಕೊಡು(INIT_SZ)) == ಖಾಲಿ)
		ಹೋಗು fail;

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	ಆದರೆ (ret >= 0 && ret < INIT_SZ) { /* succeeded with initial alloc */
		*str = string;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ret == ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ || ret < 0) { /* Bad length */
		ಬಿಡುಗಡೆ(string);
		ಹೋಗು fail;
	} ಇಲ್ಲದಿದ್ದರೆ {	/* bigger than initial, realloc allowing for nul */
		len = (ಗಾತ್ರ_t)ret + 1;
		ಆದರೆ ((newstr = realloc(string, len)) == ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(string);
			ಹೋಗು fail;
		} ಇಲ್ಲದಿದ್ದರೆ {
			va_end(ap2);
			VA_COPY(ap2, ap);
			ret = vsnprintf(newstr, len, fmt, ap2);
			ಆದರೆ (ret >= 0 && (ಗಾತ್ರ_t)ret < len) {
				*str = newstr;
			} ಇಲ್ಲದಿದ್ದರೆ { /* failed with realloc'ed string, give up */
				ಬಿಡುಗಡೆ(newstr);
				ಹೋಗು fail;
			}
		}
	}
	va_end(ap2);
	ಹಿಂತಿರುಗಿ (ret);

fail:
	*str = ಖಾಲಿ;
	errno = ENOMEM;
	va_end(ap2);
	ಹಿಂತಿರುಗಿ (-1);
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_ASPRINTF
ಪೂರ್ಣಾಂಕ asprintf(ಅಕ್ಷರ **str, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ap;
	ಪೂರ್ಣಾಂಕ ret;

	*str = ಖಾಲಿ;
	va_start(ap, fmt);
	ret = vasprintf(str, fmt, ap);
	va_end(ap);

	ಹಿಂತಿರುಗಿ ret;
}
#ಆದರೆ_ಅಂತ್ಯ
